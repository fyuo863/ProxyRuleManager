//go:build windows

package tun

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/prmfs"
)

const (
	transparentLogName   = "app-transparent.log"
	bundledDriverDirName = "windivert"
	transparentFWGroup   = "ProxyRuleManager Transparent Capture"
)

type WindowsService struct {
	mu          sync.RWMutex
	running     bool
	lastMessage string
	startedAt   time.Time
	packetCount uint64
	byteCount   uint64
	logPath     string
	driverPath  string
	stopCh      chan struct{}
	wg          sync.WaitGroup

	api           *winDivertAPI
	networkHandle windows.Handle
	socketHandle  windows.Handle

	logMu       sync.Mutex
	logFile     *os.File
	options     model.TunOptions
	queries     []string
	connections map[uint16]*redirectConnection
	byRedirect  map[uint16]*redirectConnection
	procCache   map[uint32]processInfo
	udpBlocked  map[string]struct{}
}

type redirectConnection struct {
	processID    uint32
	processName  string
	processPath  string
	localAddr    net.IP
	localPort    uint16
	remoteAddr   net.IP
	remotePort   uint16
	redirectPort uint16
	listener     net.Listener
	createdAt    time.Time
	accepted     atomic.Bool
}

type processInfo struct {
	pid  uint32
	name string
	path string
}

func NewService() Service {
	return &WindowsService{}
}

func (s *WindowsService) Start(options model.TunOptions) error {
	status := s.Status(options)
	if !status.Available {
		return errors.New(status.Message)
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	runtimeDir, err := runtimeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return err
	}

	driverDLL, err := ensureWinDivertRuntime(runtimeDir)
	if err != nil {
		return err
	}
	api, err := loadWinDivertAPI(driverDLL)
	if err != nil {
		return fmt.Errorf("加载 WinDivert 失败: %w", err)
	}

	logPath := filepath.Join(runtimeDir, transparentLogName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	socketHandle, err := api.open(
		"tcp and (event == CONNECT or event == CLOSE) and localAddr != :: and remoteAddr != ::",
		windivertLayerSocket,
		1500,
		windivertFlagRecvOnly|windivertFlagSniff,
	)
	if err != nil {
		_ = logFile.Close()
		return fmt.Errorf("打开 WinDivert SOCKET 层失败: %w", err)
	}
	networkHandle, err := api.open(
		"outbound and tcp and ip and !loopback",
		windivertLayerNetwork,
		1000,
		0,
	)
	if err != nil {
		_ = api.close(socketHandle)
		_ = logFile.Close()
		return fmt.Errorf("打开 WinDivert NETWORK 层失败: %w", err)
	}
	_ = api.setParam(networkHandle, windivertParamQueueLength, 8192)
	_ = api.setParam(networkHandle, windivertParamQueueSize, 8*1024*1024)
	_ = api.setParam(networkHandle, windivertParamQueueTime, 2000)

	s.mu.Lock()
	s.api = api
	s.socketHandle = socketHandle
	s.networkHandle = networkHandle
	s.logFile = logFile
	s.options = options
	s.queries = normalizeApps(options.IncludedApps)
	s.connections = map[uint16]*redirectConnection{}
	s.byRedirect = map[uint16]*redirectConnection{}
	s.procCache = map[uint32]processInfo{}
	s.udpBlocked = map[string]struct{}{}
	s.stopCh = make(chan struct{})
	s.running = true
	s.startedAt = time.Now()
	s.logPath = logPath
	s.driverPath = driverDLL
	s.lastMessage = fmt.Sprintf("应用级透明接管已启动，当前接管 %d 个目标应用（TCP）", len(s.queries))
	s.mu.Unlock()

	s.logf("service started; upstream=%s type=%s targets=%v", options.FastLinkAddr, options.FastLinkType, s.queries)

	s.wg.Add(3)
	go s.socketLoop()
	go s.networkLoop()
	go s.reaperLoop()
	return nil
}

func (s *WindowsService) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.running = false
		s.lastMessage = "应用级透明接管未运行"
		s.mu.Unlock()
		return nil
	}
	stopCh := s.stopCh
	s.stopCh = nil
	socketHandle := s.socketHandle
	networkHandle := s.networkHandle
	s.running = false
	s.socketHandle = 0
	s.networkHandle = 0
	for _, conn := range s.connections {
		_ = conn.listener.Close()
	}
	s.lastMessage = "正在停止应用级透明接管"
	s.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if s.api != nil {
		if socketHandle != 0 {
			_ = s.api.close(socketHandle)
		}
		if networkHandle != 0 {
			_ = s.api.close(networkHandle)
		}
	}
	s.wg.Wait()

	if err := clearTransparentFirewallRules(); err != nil {
		s.logf("clear transparent firewall rules failed: %v", err)
	}

	s.logMu.Lock()
	if s.logFile != nil {
		_ = s.logFile.Close()
		s.logFile = nil
	}
	s.logMu.Unlock()

	s.mu.Lock()
	s.connections = nil
	s.byRedirect = nil
	s.procCache = nil
	s.lastMessage = "应用级透明接管已停止"
	s.mu.Unlock()
	return nil
}

func (s *WindowsService) Status(options model.TunOptions) model.TunRuntimeStatus {
	if !isAdministrator() {
		return model.TunRuntimeStatus{
			Running:   false,
			Available: false,
			Message:   "应用级透明接管需要以管理员身份运行程序",
		}
	}
	if strings.TrimSpace(options.FastLinkAddr) == "" {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "上游代理地址为空",
		}
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(options.FastLinkAddr)); err != nil {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "上游代理地址格式无效，应为 host:port",
		}
	}
	switch strings.ToLower(strings.TrimSpace(options.FastLinkType)) {
	case "", "http", "socks", "socks5":
	default:
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "当前仅支持 HTTP CONNECT 或 SOCKS5 上游",
		}
	}
	if len(normalizeApps(options.IncludedApps)) == 0 {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "请至少配置一个需要透明接管的应用进程名或路径",
		}
	}
	if _, err := bundledWinDivertDir(); err != nil {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   err.Error(),
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	message := s.lastMessage
	if message == "" {
		message = "已就绪：指定应用的 TCP 连接将被透明反射到本地代理，再经上游代理建隧道；已识别路径的 UDP 会被阻断以防旁路"
	}
	return model.TunRuntimeStatus{
		Running:     s.running,
		Available:   true,
		Message:     message,
		PacketCount: atomic.LoadUint64(&s.packetCount),
		ByteCount:   atomic.LoadUint64(&s.byteCount),
	}
}

func (s *WindowsService) socketLoop() {
	defer s.wg.Done()
	for {
		if !s.isRunning() {
			return
		}
		var addr winDivertAddress
		_, err := s.api.recv(s.socketHandle, nil, &addr)
		if err != nil {
			if !s.isRunning() || isClosedHandleErr(err) {
				return
			}
			s.logf("socket recv error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		socket := addr.socket()
		if socket.Protocol != 6 {
			continue
		}
		localIP := ipv4FromMapped(socket.LocalAddr)
		remoteIP := ipv4FromMapped(socket.RemoteAddr)
		if localIP == nil || remoteIP == nil {
			continue
		}

		switch addr.event() {
		case windivertEventSocketConnect:
			proc := s.lookupProcess(socket.ProcessID)
			query, ok := matchProcessQuery(proc, s.currentQueries())
			if !ok {
				continue
			}
			if err := s.registerConnection(proc, query, localIP, socket.LocalPort, remoteIP, socket.RemotePort); err != nil {
				s.logf("register redirect failed pid=%d local=%s:%d remote=%s:%d: %v", proc.pid, localIP, socket.LocalPort, remoteIP, socket.RemotePort, err)
			}
			if proc.path != "" {
				if err := s.ensureUDPBlock(proc.path); err != nil {
					s.logf("udp block rule failed for %s: %v", proc.path, err)
				}
			}
		case windivertEventSocketClose:
			s.unregisterConnection(socket.LocalPort)
		}
	}
}

func (s *WindowsService) networkLoop() {
	defer s.wg.Done()
	packet := make([]byte, 65535)
	for {
		if !s.isRunning() {
			return
		}
		var addr winDivertAddress
		n, err := s.api.recv(s.networkHandle, packet, &addr)
		if err != nil {
			if !s.isRunning() || isClosedHandleErr(err) {
				return
			}
			s.logf("network recv error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		buf := append([]byte(nil), packet[:n]...)
		view, ok := parseIPv4TCPPacket(buf)
		if !ok {
			_ = s.api.send(s.networkHandle, buf, &addr)
			continue
		}

		if conn := s.connectionByRedirect(view.srcPort); conn != nil && conn.remotePort == view.dstPort && conn.remoteAddr.Equal(view.dstIP) {
			view.setSrcIP(conn.remoteAddr)
			view.setDstIP(conn.localAddr)
			view.setSrcPort(conn.remotePort)
			view.setDstPort(conn.localPort)
			addr.setOutbound(false)
			if err := s.api.calcChecksums(buf, &addr); err != nil {
				s.logf("checksum reverse reflect failed: %v", err)
			}
			if err := s.api.send(s.networkHandle, buf, &addr); err != nil {
				s.logf("reverse reflect send failed: %v", err)
			} else {
				atomic.AddUint64(&s.packetCount, 1)
				atomic.AddUint64(&s.byteCount, uint64(len(buf)))
			}
			continue
		}

		if conn := s.connectionByLocal(view.srcPort); conn != nil && conn.remotePort == view.dstPort && conn.remoteAddr.Equal(view.dstIP) {
			view.setDstPort(conn.redirectPort)
			view.setDstIP(view.srcIP)
			view.setSrcIP(conn.remoteAddr)
			addr.setOutbound(false)
			if err := s.api.calcChecksums(buf, &addr); err != nil {
				s.logf("checksum forward reflect failed: %v", err)
			}
			if err := s.api.send(s.networkHandle, buf, &addr); err != nil {
				s.logf("forward reflect send failed: %v", err)
			} else {
				atomic.AddUint64(&s.packetCount, 1)
				atomic.AddUint64(&s.byteCount, uint64(len(buf)))
			}
			continue
		}

		if err := s.api.send(s.networkHandle, buf, &addr); err != nil && s.isRunning() {
			s.logf("passthrough send failed: %v", err)
		}
	}
}

func (s *WindowsService) reaperLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapStaleConnections()
		case <-s.stopChannel():
			return
		}
	}
}

func (s *WindowsService) registerConnection(proc processInfo, query string, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) error {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return errors.New("unexpected listener address")
	}

	conn := &redirectConnection{
		processID:    proc.pid,
		processName:  proc.name,
		processPath:  proc.path,
		localAddr:    append(net.IP(nil), localIP...),
		localPort:    localPort,
		remoteAddr:   append(net.IP(nil), remoteIP...),
		remotePort:   remotePort,
		redirectPort: uint16(tcpAddr.Port),
		listener:     listener,
		createdAt:    time.Now(),
	}

	s.mu.Lock()
	if old := s.connections[localPort]; old != nil {
		_ = old.listener.Close()
		delete(s.byRedirect, old.redirectPort)
	}
	s.connections[localPort] = conn
	s.byRedirect[conn.redirectPort] = conn
	s.mu.Unlock()

	s.logf("redirect prepared query=%s pid=%d %s:%d -> %s:%d via local-port=%d", query, proc.pid, conn.localAddr, conn.localPort, conn.remoteAddr, conn.remotePort, conn.redirectPort)
	s.wg.Add(1)
	go s.serveReflectedConnection(conn)
	return nil
}

func (s *WindowsService) unregisterConnection(localPort uint16) {
	s.mu.Lock()
	conn := s.connections[localPort]
	if conn != nil {
		delete(s.connections, localPort)
		delete(s.byRedirect, conn.redirectPort)
		_ = conn.listener.Close()
	}
	s.mu.Unlock()
}

func (s *WindowsService) reapStaleConnections() {
	cutoff := time.Now().Add(-45 * time.Second)
	var stale []*redirectConnection
	s.mu.Lock()
	for port, conn := range s.connections {
		if !conn.accepted.Load() && conn.createdAt.Before(cutoff) {
			delete(s.connections, port)
			delete(s.byRedirect, conn.redirectPort)
			stale = append(stale, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range stale {
		s.logf("stale redirect removed pid=%d local-port=%d redirect-port=%d", conn.processID, conn.localPort, conn.redirectPort)
		_ = conn.listener.Close()
	}
}

func (s *WindowsService) serveReflectedConnection(rc *redirectConnection) {
	defer s.wg.Done()
	defer rc.listener.Close()

	tcpListener, ok := rc.listener.(*net.TCPListener)
	if ok {
		_ = tcpListener.SetDeadline(time.Now().Add(30 * time.Second))
	}
	appConn, err := rc.listener.Accept()
	if err != nil {
		if s.isRunning() && !errors.Is(err, net.ErrClosed) {
			s.logf("accept reflected connection failed: %v", err)
		}
		return
	}
	defer appConn.Close()
	rc.accepted.Store(true)

	upstreamCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	upstreamConn, err := s.dialUpstream(upstreamCtx, net.JoinHostPort(rc.remoteAddr.String(), fmt.Sprintf("%d", rc.remotePort)))
	if err != nil {
		s.logf("dial upstream failed for %s:%d: %v", rc.remoteAddr, rc.remotePort, err)
		return
	}
	defer upstreamConn.Close()

	s.logf("transparent tunnel established pid=%d %s -> %s:%d", rc.processID, rc.processName, rc.remoteAddr, rc.remotePort)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(upstreamConn, appConn)
	}()
	go func() {
		defer wg.Done()
		pipe(appConn, upstreamConn)
	}()
	wg.Wait()
	time.AfterFunc(15*time.Second, func() {
		s.unregisterConnection(rc.localPort)
	})
}

func (s *WindowsService) dialUpstream(ctx context.Context, destination string) (net.Conn, error) {
	upstreamAddr := strings.TrimSpace(s.options.FastLinkAddr)
	upstreamType := strings.ToLower(strings.TrimSpace(s.options.FastLinkType))
	if upstreamType == "" {
		upstreamType = "http"
	}
	dialer := &net.Dialer{}

	switch upstreamType {
	case "http":
		conn, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
		if err != nil {
			return nil, err
		}
		if err := writeHTTPConnect(conn, destination); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	case "socks", "socks5":
		base, err := proxy.SOCKS5("tcp", upstreamAddr, nil, dialer)
		if err != nil {
			return nil, err
		}
		if contextDialer, ok := base.(proxy.ContextDialer); ok {
			return contextDialer.DialContext(ctx, "tcp", destination)
		}
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			conn, err := base.Dial("tcp", destination)
			done <- result{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case out := <-done:
			return out.conn, out.err
		}
	default:
		return nil, fmt.Errorf("unsupported upstream type: %s", upstreamType)
	}
}

func writeHTTPConnect(conn net.Conn, destination string) error {
	if deadlineConn, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetDeadline(time.Now().Add(12 * time.Second))
		defer deadlineConn.SetDeadline(time.Time{})
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", destination, destination); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(status, " 200 ") {
		return fmt.Errorf("upstream CONNECT failed: %s", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			break
		}
	}
	if buffered := reader.Buffered(); buffered > 0 {
		return errors.New("unexpected buffered data after CONNECT response")
	}
	return nil
}

func parseIPv4TCPPacket(packet []byte) (*ipv4TCPPacket, bool) {
	if len(packet) < 20 {
		return nil, false
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil, false
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return nil, false
	}
	if packet[9] != 6 {
		return nil, false
	}
	return &ipv4TCPPacket{
		raw:     packet,
		ihl:     ihl,
		srcIP:   net.IPv4(packet[12], packet[13], packet[14], packet[15]).To4(),
		dstIP:   net.IPv4(packet[16], packet[17], packet[18], packet[19]).To4(),
		srcPort: binary.BigEndian.Uint16(packet[ihl : ihl+2]),
		dstPort: binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]),
	}, true
}

type ipv4TCPPacket struct {
	raw     []byte
	ihl     int
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
}

func (p *ipv4TCPPacket) setSrcIP(ip net.IP) {
	copy(p.raw[12:16], ip.To4())
}

func (p *ipv4TCPPacket) setDstIP(ip net.IP) {
	copy(p.raw[16:20], ip.To4())
}

func (p *ipv4TCPPacket) setSrcPort(port uint16) {
	binary.BigEndian.PutUint16(p.raw[p.ihl:p.ihl+2], port)
}

func (p *ipv4TCPPacket) setDstPort(port uint16) {
	binary.BigEndian.PutUint16(p.raw[p.ihl+2:p.ihl+4], port)
}

func (s *WindowsService) lookupProcess(pid uint32) processInfo {
	s.mu.RLock()
	if proc, ok := s.procCache[pid]; ok {
		s.mu.RUnlock()
		return proc
	}
	s.mu.RUnlock()

	path := queryProcessPath(pid)
	proc := processInfo{
		pid:  pid,
		path: path,
		name: filepath.Base(path),
	}
	if proc.name == "" {
		proc.name = fmt.Sprintf("pid-%d", pid)
	}

	s.mu.Lock()
	if s.procCache != nil {
		s.procCache[pid] = proc
	}
	s.mu.Unlock()
	return proc
}

func queryProcessPath(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func matchProcessQuery(proc processInfo, queries []string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(proc.name))
	path := strings.ToLower(strings.TrimSpace(proc.path))
	for _, raw := range queries {
		query := strings.ToLower(strings.TrimSpace(raw))
		if query == "" {
			continue
		}
		if strings.Contains(query, "\\") || strings.Contains(query, "/") || strings.Contains(query, ":") {
			if path != "" && (path == query || strings.HasSuffix(path, query)) {
				return raw, true
			}
			if strings.HasSuffix(name, strings.ToLower(baseName(query))) {
				return raw, true
			}
			continue
		}
		if name == query {
			return raw, true
		}
	}
	return "", false
}

func normalizeApps(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	idx := strings.LastIndex(path, "\\")
	if idx >= 0 && idx+1 < len(path) {
		return path[idx+1:]
	}
	return path
}

func ipv4FromMapped(words [4]uint32) net.IP {
	raw := (*[16]byte)(unsafe.Pointer(&words[0]))
	if raw[10] == 0xFF && raw[11] == 0xFF {
		return net.IPv4(raw[12], raw[13], raw[14], raw[15]).To4()
	}
	if raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		return net.IPv4(raw[12], raw[13], raw[14], raw[15]).To4()
	}
	return nil
}

func ensureWinDivertRuntime(runtimeDir string) (string, error) {
	sourceDir, err := bundledWinDivertDir()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		src := filepath.Join(sourceDir, name)
		dst := filepath.Join(runtimeDir, name)
		if err := copyFile(src, dst); err != nil {
			return "", err
		}
	}
	return filepath.Join(runtimeDir, "WinDivert.dll"), nil
}

func bundledWinDivertDir() (string, error) {
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "third_party", bundledDriverDirName))
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "third_party", bundledDriverDirName),
			filepath.Join(exeDir, bundledDriverDirName),
		)
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "WinDivert.dll")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "WinDivert64.sys")); err == nil {
				return dir, nil
			}
		}
	}
	return "", errors.New("未找到内置 WinDivert 运行文件，请确认 third_party/windivert 已随程序提供")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func runtimeDir() (string, error) {
	return prmfs.TunRuntimeDir()
}

func driverDir() (string, error) {
	return bundledWinDivertDir()
}

func (s *WindowsService) connectionByLocal(port uint16) *redirectConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connections[port]
}

func (s *WindowsService) connectionByRedirect(port uint16) *redirectConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byRedirect[port]
}

func (s *WindowsService) currentQueries() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.queries))
	copy(out, s.queries)
	return out
}

func (s *WindowsService) ensureUDPBlock(processPath string) error {
	key := strings.ToLower(strings.TrimSpace(processPath))
	if key == "" {
		return nil
	}
	s.mu.RLock()
	_, exists := s.udpBlocked[key]
	s.mu.RUnlock()
	if exists {
		return nil
	}
	if _, err := runPowerShell(addTransparentUDPBlockScript(processPath)); err != nil {
		return err
	}
	s.mu.Lock()
	if s.udpBlocked != nil {
		s.udpBlocked[key] = struct{}{}
	}
	s.mu.Unlock()
	return nil
}

func (s *WindowsService) stopChannel() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stopCh
}

func (s *WindowsService) isRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *WindowsService) logf(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if s.logFile != nil {
		_, _ = s.logFile.WriteString(line)
	}
}

func isAdministrator() bool {
	token := windows.GetCurrentProcessToken()
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := token.IsMember(adminSid)
	return err == nil && member
}

func isClosedHandleErr(err error) bool {
	return errors.Is(err, syscall.Errno(windows.ERROR_INVALID_HANDLE)) ||
		errors.Is(err, syscall.Errno(windows.ERROR_OPERATION_ABORTED))
}

func clearTransparentFirewallRules() error {
	_, err := runPowerShell("$group = '" + psLiteral(transparentFWGroup) + "'\n" +
		"Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null\n")
	return err
}

func addTransparentUDPBlockScript(processPath string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$group = '")
	b.WriteString(psLiteral(transparentFWGroup))
	b.WriteString("'\n")
	b.WriteString("$program = (Resolve-Path -LiteralPath '")
	b.WriteString(psLiteral(processPath))
	b.WriteString("').Path\n")
	b.WriteString("$name = [System.IO.Path]::GetFileName($program)\n")
	b.WriteString("$display = 'Transparent UDP Block - ' + $name\n")
	b.WriteString("$exists = Get-NetFirewallRule -Group $group -DisplayName $display -ErrorAction SilentlyContinue\n")
	b.WriteString("if (-not $exists) {\n")
	b.WriteString("  New-NetFirewallRule -DisplayName $display -Group $group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $program -Protocol UDP | Out-Null\n")
	b.WriteString("}\n")
	return b.String()
}

func psLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%s", message)
	}
	return strings.TrimSpace(string(output)), nil
}
