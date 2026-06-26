package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"proxy-rule-manager/internal/model"
)

type MatchFunc func(host string) (model.Rule, model.MatchedRule)
type AddLogFunc func(entry model.TrafficLog)
type UpdateLogFunc func(id string, mutator func(*model.TrafficLog))

type Server struct {
	addr         string
	fastLinkAddr string
	match        MatchFunc
	addLog       AddLogFunc
	updateLog    UpdateLogFunc

	server   *http.Server
	listener net.Listener
	mu       sync.RWMutex
}

func NewServer(addr, fastLinkAddr string, match MatchFunc, addLog AddLogFunc, updateLog UpdateLogFunc) *Server {
	return &Server{
		addr:         addr,
		fastLinkAddr: fastLinkAddr,
		match:        match,
		addLog:       addLog,
		updateLog:    updateLog,
	}
}

func (s *Server) Start() error {
	mux := http.HandlerFunc(s.handleHTTP)
	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = listener

	go func() {
		_ = s.server.Serve(listener)
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil || s.listener == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	s.listener = nil
	return err
}

func (s *Server) UpdateSettings(addr, fastLinkAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = addr
	s.fastLinkAddr = fastLinkAddr
}

func (s *Server) currentFastLinkAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fastLinkAddr
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		s.handleConnect(w, r)
		return
	}
	s.handleForwardHTTP(w, r)
}

func (s *Server) handleForwardHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(defaultHTTPHost(r))
	rule, matched := s.match(host)
	logEntry := model.TrafficLog{
		ID:               uuid.NewString(),
		Time:             time.Now().Format(time.RFC3339),
		Host:             host,
		Port:             port,
		Protocol:         "HTTP",
		MatchedRuleType:  matched.Type,
		MatchedRuleValue: matched.Value,
		MatchedRuleIndex: matched.Index,
		Target:           rule.Target,
		Path:             describePath(rule.Target, s.currentFastLinkAddr()),
		Status:           model.TrafficStatusActive,
	}
	s.addLog(logEntry)

	started := time.Now()

	if rule.Target == model.RuleTargetReject {
		http.Error(w, "blocked by rule", http.StatusForbidden)
		s.finishLog(logEntry.ID, started, 0, 0, model.TrafficStatusClosed, "")
		return
	}

	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")

	var uploadCounter int64
	if req.Body != nil {
		req.Body = &countingReadCloser{ReadCloser: req.Body, count: &uploadCounter}
	}

	client := &http.Client{
		Transport: s.buildTransport(rule.Target),
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		s.finishLog(logEntry.ID, started, uploadCounter, 0, model.TrafficStatusError, err.Error())
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	downloadCounter, copyErr := io.Copy(w, resp.Body)
	status := model.TrafficStatusClosed
	errMsg := ""
	if copyErr != nil {
		status = model.TrafficStatusError
		errMsg = copyErr.Error()
	}
	s.finishLog(logEntry.ID, started, uploadCounter, downloadCounter, status, errMsg)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host)
	rule, matched := s.match(host)
	started := time.Now()

	logEntry := model.TrafficLog{
		ID:               uuid.NewString(),
		Time:             time.Now().Format(time.RFC3339),
		Host:             host,
		Port:             port,
		Protocol:         "HTTPS CONNECT",
		MatchedRuleType:  matched.Type,
		MatchedRuleValue: matched.Value,
		MatchedRuleIndex: matched.Index,
		Target:           rule.Target,
		Path:             describePath(rule.Target, s.currentFastLinkAddr()),
		Status:           model.TrafficStatusActive,
	}
	s.addLog(logEntry)

	if rule.Target == model.RuleTargetReject {
		http.Error(w, "blocked by rule", http.StatusForbidden)
		s.finishLog(logEntry.ID, started, 0, 0, model.TrafficStatusClosed, "")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		s.finishLog(logEntry.ID, started, 0, 0, model.TrafficStatusError, "hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.finishLog(logEntry.ID, started, 0, 0, model.TrafficStatusError, err.Error())
		return
	}

	upstreamConn, err := s.connectTunnel(r.Context(), rule.Target, r.Host)
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientConn.Close()
		s.finishLog(logEntry.ID, started, 0, 0, model.TrafficStatusError, err.Error())
		return
	}

	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	var uploadBytes int64
	var downloadBytes int64
	errCh := make(chan error, 2)

	go copyTunnel(clientConn, upstreamConn, &uploadBytes, errCh)
	go copyTunnel(upstreamConn, clientConn, &downloadBytes, errCh)

	var finalErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !isConnClosedErr(err) {
			finalErr = err
		}
	}

	_ = clientConn.Close()
	_ = upstreamConn.Close()

	status := model.TrafficStatusClosed
	errMsg := ""
	if finalErr != nil {
		status = model.TrafficStatusError
		errMsg = finalErr.Error()
	}
	s.finishLog(logEntry.ID, started, uploadBytes, downloadBytes, status, errMsg)
}

func (s *Server) connectTunnel(ctx context.Context, target model.RuleTarget, hostPort string) (net.Conn, error) {
	if target == model.RuleTargetDirect {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, "tcp", hostPort)
	}

	fastLinkAddr := s.currentFastLinkAddr()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", fastLinkAddr)
	if err != nil {
		return nil, err
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", hostPort, hostPort); err != nil {
		_ = conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", resp.Status)
	}

	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (s *Server) buildTransport(target model.RuleTarget) http.RoundTripper {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
	if target == model.RuleTargetProxy {
		proxyURL := &url.URL{Scheme: "http", Host: s.currentFastLinkAddr()}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return transport
}

func (s *Server) finishLog(id string, started time.Time, uploadBytes, downloadBytes int64, status model.TrafficStatus, errMsg string) {
	s.updateLog(id, func(item *model.TrafficLog) {
		item.UploadBytes = uploadBytes
		item.DownloadBytes = downloadBytes
		item.DurationMs = time.Since(started).Milliseconds()
		item.Status = status
		item.Error = errMsg
	})
}

func defaultHTTPHost(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

func splitHostPort(hostPort string) (string, string) {
	if strings.Contains(hostPort, ":") {
		host, port, err := net.SplitHostPort(hostPort)
		if err == nil {
			return strings.Trim(host, "[]"), port
		}
		if strings.Count(hostPort, ":") == 1 {
			parts := strings.SplitN(hostPort, ":", 2)
			return parts[0], parts[1]
		}
	}
	if strings.HasPrefix(hostPort, "[") && strings.Contains(hostPort, "]") {
		host := strings.TrimPrefix(strings.Split(hostPort, "]")[0], "[")
		return host, "443"
	}
	return hostPort, "80"
}

func describePath(target model.RuleTarget, fastLinkAddr string) string {
	switch target {
	case model.RuleTargetProxy:
		return fmt.Sprintf("本程序 -> FastLink %s -> Wi-Fi", fastLinkAddr)
	case model.RuleTargetReject:
		return "本程序拒绝连接"
	default:
		return "本程序 -> 目标网站 -> Windows 默认路由/有线"
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copyTunnel(dst net.Conn, src net.Conn, counter *int64, errCh chan<- error) {
	written, err := io.Copy(dst, src)
	atomic.AddInt64(counter, written)
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	} else {
		_ = dst.Close()
	}
	errCh <- err
}

func isConnClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(strings.ToLower(err.Error()), "closed")
}

type countingReadCloser struct {
	io.ReadCloser
	count *int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	atomic.AddInt64(c.count, int64(n))
	return n, err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
