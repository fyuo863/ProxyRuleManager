//go:build windows

package tun

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/netadapter"
	"proxy-rule-manager/internal/prmfs"
	"proxy-rule-manager/internal/procmatch"
	"proxy-rule-manager/internal/winps"
)

const (
	transparentLogName   = "app-transparent.log"
	bundledDriverDirName = "windivert"
	transparentFWGroup   = "ProxyRuleManager Transparent Capture"
	networkIdleFilter    = "tcp and ip and !loopback and tcp.SrcPort == 0 and tcp.DstPort == 0"
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
	networkMu     sync.RWMutex
	networkFilter string

	logMu       sync.Mutex
	logFile     *os.File
	options     model.TunOptions
	profiles    []resolvedTunAppProfile
	queryMap    map[string]resolvedTunAppProfile
	queries     []string
	configPath  string
	connections map[uint16]*redirectConnection
	byRedirect  map[uint16]*redirectConnection
	procCache   map[uint32]processInfo
	udpBlocked  map[string]struct{}
	udpBlocking map[string]*udpBlockCall

	socketConnectEvents uint64
	matchedConnects     uint64
	redirectPrepared    uint64
	acceptCount         uint64
	upstreamDialFailed  uint64
	tunnelEstablished   uint64
	forwardReflected    uint64
	reverseReflected    uint64
	lastSocketError     string
	lastUpstreamError   string
	lastMatchedProcess  string
}

type runtimeSnapshot struct {
	GeneratedAt           string           `json:"generatedAt"`
	Running               bool             `json:"running"`
	Message               string           `json:"message"`
	LogPath               string           `json:"logPath"`
	DriverPath            string           `json:"driverPath"`
	Options               model.TunOptions `json:"options"`
	Queries               []string         `json:"queries"`
	SocketConnectEvents   uint64           `json:"socketConnectEvents"`
	MatchedConnects       uint64           `json:"matchedConnects"`
	RedirectPreparedCount uint64           `json:"redirectPreparedCount"`
	AcceptCount           uint64           `json:"acceptCount"`
	UpstreamDialFailures  uint64           `json:"upstreamDialFailures"`
	TunnelEstablished     uint64           `json:"tunnelEstablished"`
	ForwardReflected      uint64           `json:"forwardReflected"`
	ReverseReflected      uint64           `json:"reverseReflected"`
	LastMatchedProcess    string           `json:"lastMatchedProcess"`
	LastSocketError       string           `json:"lastSocketError"`
	LastUpstreamError     string           `json:"lastUpstreamError"`
}

type udpBlockCall struct {
	done chan struct{}
	err  error
}

type redirectConnection struct {
	processID    uint32
	processName  string
	processPath  string
	query        string
	profileID    string
	profileName  string
	routingMode  model.TunAppRoutingMode
	ifIdx        uint32
	subIfIdx     uint32
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

type resolvedTunAppProfile struct {
	ID          string
	Name        string
	RoutingMode model.TunAppRoutingMode
	Remark      string
	Queries     []string
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
	configPath := filepath.Join(runtimeDir, "transparent-runtime.json")
	if err := ensureTransparentTCPAllow(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("配置透明捕获防火墙规则失败: %w", err)
	}

	socketHandle, err := api.open(
		"event == CONNECT or event == CLOSE",
		windivertLayerSocket,
		1500,
		windivertFlagRecvOnly|windivertFlagSniff,
	)
	if err != nil {
		_ = logFile.Close()
		return fmt.Errorf("打开 WinDivert SOCKET 层失败: %w", err)
	}
	networkHandle, err := api.open(
		networkIdleFilter,
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
	s.networkFilter = networkIdleFilter
	s.logFile = logFile
	s.options = options
	s.profiles = resolveTunAppProfiles(options.AppProfiles, options.IncludedApps)
	s.queries = flattenResolvedTunQueries(s.profiles)
	s.queryMap = buildResolvedTunQueryMap(s.profiles)
	s.connections = map[uint16]*redirectConnection{}
	s.byRedirect = map[uint16]*redirectConnection{}
	s.procCache = map[uint32]processInfo{}
	s.udpBlocked = map[string]struct{}{}
	s.udpBlocking = map[string]*udpBlockCall{}
	s.stopCh = make(chan struct{})
	s.running = true
	s.startedAt = time.Now()
	s.logPath = logPath
	s.configPath = configPath
	s.driverPath = driverDLL
	s.lastMessage = fmt.Sprintf("应用级透明接管已启动，当前接管 %d 个目标应用（TCP）", len(s.queries))
	s.socketConnectEvents = 0
	s.matchedConnects = 0
	s.redirectPrepared = 0
	s.acceptCount = 0
	s.upstreamDialFailed = 0
	s.tunnelEstablished = 0
	s.forwardReflected = 0
	s.reverseReflected = 0
	s.lastSocketError = ""
	s.lastUpstreamError = ""
	s.lastMatchedProcess = ""
	s.mu.Unlock()

	s.logf("service started; upstream=%s type=%s targets=%v", options.UpstreamProxyAddr, options.UpstreamProxyType, s.queries)
	s.persistRuntimeSnapshot()

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
	s.running = false
	s.socketHandle = 0
	for _, conn := range s.connections {
		_ = conn.listener.Close()
	}
	s.lastMessage = "正在停止应用级透明接管"
	s.mu.Unlock()

	s.networkMu.Lock()
	networkHandle := s.networkHandle
	s.networkHandle = 0
	s.networkFilter = ""
	s.networkMu.Unlock()

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
	s.udpBlocked = nil
	s.udpBlocking = nil
	s.lastMessage = "应用级透明接管已停止"
	s.mu.Unlock()
	s.persistRuntimeSnapshot()
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
	if strings.TrimSpace(options.UpstreamProxyAddr) == "" {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "上游代理地址为空",
		}
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(options.UpstreamProxyAddr)); err != nil {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "上游代理地址格式无效，应为 host:port",
		}
	}
	switch strings.ToLower(strings.TrimSpace(options.UpstreamProxyType)) {
	case "", "http", "socks", "socks5":
	default:
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "当前仅支持 HTTP CONNECT 或 SOCKS5 上游",
		}
	}
	if len(flattenResolvedTunQueries(resolveTunAppProfiles(options.AppProfiles, options.IncludedApps))) == 0 {
		return model.TunRuntimeStatus{
			Running:   s.isRunning(),
			Available: false,
			Message:   "请至少配置一个需要透明接管的应用进程名或路径",
		}
	}
	if _, err := winDivertRuntimeDir(); err != nil {
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
			s.recordSocketError(err)
			s.logf("socket recv error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		socket := addr.socket()
		event := addr.event()
		if event == windivertEventSocketConnect {
			atomic.AddUint64(&s.socketConnectEvents, 1)
		}
		proc := s.lookupProcess(socket.ProcessID)
		trackedProcess := strings.Contains(strings.ToLower(proc.name), "codex") || strings.Contains(strings.ToLower(proc.path), "codex")
		if socket.Protocol != 6 {
			if trackedProcess && event == windivertEventSocketConnect {
				s.logf("socket connect skipped non-tcp pid=%d proc=%s proto=%d local-port=%d remote-port=%d flags=%08x", proc.pid, proc.path, socket.Protocol, socket.LocalPort, socket.RemotePort, addr.Flags)
			}
			continue
		}
		localIP := ipv4FromMapped(socket.LocalAddr)
		remoteIP := ipv4FromMapped(socket.RemoteAddr)
		if localIP == nil || remoteIP == nil {
			if trackedProcess && event == windivertEventSocketConnect {
				s.logf("socket connect skipped non-ipv4 pid=%d proc=%s local-raw=%08x,%08x,%08x,%08x remote-raw=%08x,%08x,%08x,%08x", proc.pid, proc.path, socket.LocalAddr[0], socket.LocalAddr[1], socket.LocalAddr[2], socket.LocalAddr[3], socket.RemoteAddr[0], socket.RemoteAddr[1], socket.RemoteAddr[2], socket.RemoteAddr[3])
			}
			continue
		}
		if localIP.IsLoopback() || remoteIP.IsLoopback() {
			if trackedProcess && event == windivertEventSocketConnect {
				s.logf("socket connect skipped loopback pid=%d proc=%s local=%s:%d remote=%s:%d", proc.pid, proc.path, localIP, socket.LocalPort, remoteIP, socket.RemotePort)
			}
			continue
		}

		switch event {
		case windivertEventSocketConnect:
			query, ok := procmatch.MatchProcess(proc.name, proc.path, s.currentQueries())
			if !ok {
				if trackedProcess {
					s.logf("socket connect ignored pid=%d proc=%s local=%s:%d remote=%s:%d queries=%v", proc.pid, proc.path, localIP, socket.LocalPort, remoteIP, socket.RemotePort, s.currentQueries())
				}
				continue
			}
			if s.shouldBypassTransparentConnect(remoteIP, socket.RemotePort) {
				s.logf("socket connect bypassed pid=%d proc=%s remote=%s:%d reason=upstream-proxy", proc.pid, proc.path, remoteIP, socket.RemotePort)
				continue
			}
			atomic.AddUint64(&s.matchedConnects, 1)
			s.recordMatchedProcess(proc)
			profile := s.profileForQuery(query)
			s.logf("socket connect matched query=%s pid=%d proc=%s local=%s:%d remote=%s:%d", query, proc.pid, proc.path, localIP, socket.LocalPort, remoteIP, socket.RemotePort)
			if err := s.registerConnection(proc, query, profile, localIP, socket.LocalPort, remoteIP, socket.RemotePort); err != nil {
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
		handle := s.currentNetworkHandle()
		if handle == 0 {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		var addr winDivertAddress
		n, err := s.api.recv(handle, packet, &addr)
		if err != nil {
			if !s.isRunning() || isClosedHandleErr(err) {
				if !s.isRunning() {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.logf("network recv error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		buf := packet[:n]
		view, ok := parseIPv4TCPPacket(buf)
		if !ok {
			_ = s.api.send(handle, buf, &addr)
			continue
		}

		if conn := s.connectionByRedirect(view.srcPort); conn != nil && conn.remotePort == view.dstPort && conn.remoteAddr.Equal(view.dstIP) {
			if addr.network().IfIdx != 0 {
				conn.ifIdx = addr.network().IfIdx
				conn.subIfIdx = addr.network().SubIfIdx
			}
			view.setSrcIP(conn.remoteAddr)
			view.setDstIP(conn.localAddr)
			view.setSrcPort(conn.remotePort)
			view.setDstPort(conn.localPort)
			addr.setOutbound(false)
			if conn.ifIdx != 0 {
				addr.network().IfIdx = conn.ifIdx
				addr.network().SubIfIdx = conn.subIfIdx
			}
			if err := s.api.calcChecksums(buf, &addr); err != nil {
				s.logf("checksum reverse reflect failed: %v", err)
			}
			if err := s.api.send(handle, buf, &addr); err != nil {
				s.logf("reverse reflect send failed: %v", err)
			} else {
				atomic.AddUint64(&s.reverseReflected, 1)
				atomic.AddUint64(&s.packetCount, 1)
				atomic.AddUint64(&s.byteCount, uint64(len(buf)))
			}
			continue
		}

		if conn := s.connectionByLocal(view.srcPort); conn != nil && conn.remotePort == view.dstPort && conn.remoteAddr.Equal(view.dstIP) {
			if addr.network().IfIdx != 0 {
				conn.ifIdx = addr.network().IfIdx
				conn.subIfIdx = addr.network().SubIfIdx
			}
			view.setDstPort(conn.redirectPort)
			view.setDstIP(view.srcIP)
			view.setSrcIP(conn.remoteAddr)
			view.setSrcPort(conn.remotePort)
			addr.setOutbound(false)
			if conn.ifIdx != 0 {
				addr.network().IfIdx = conn.ifIdx
				addr.network().SubIfIdx = conn.subIfIdx
			}
			if err := s.api.calcChecksums(buf, &addr); err != nil {
				s.logf("checksum forward reflect failed: %v", err)
			}
			if err := s.api.send(handle, buf, &addr); err != nil {
				s.logf("forward reflect send failed: %v", err)
			} else {
				atomic.AddUint64(&s.forwardReflected, 1)
				atomic.AddUint64(&s.packetCount, 1)
				atomic.AddUint64(&s.byteCount, uint64(len(buf)))
			}
			continue
		}

		if err := s.api.send(handle, buf, &addr); err != nil && s.isRunning() {
			s.logf("passthrough send failed: %v", err)
		}
	}
}

func (s *WindowsService) currentNetworkHandle() windows.Handle {
	s.networkMu.RLock()
	defer s.networkMu.RUnlock()
	return s.networkHandle
}

func (s *WindowsService) refreshNetworkFilter() {
	if !s.isRunning() || s.api == nil {
		return
	}
	filter := s.buildNetworkFilter()

	s.networkMu.Lock()
	if filter == s.networkFilter {
		s.networkMu.Unlock()
		return
	}
	newHandle, err := s.api.open(filter, windivertLayerNetwork, 1000, 0)
	if err != nil {
		s.networkMu.Unlock()
		s.logf("refresh network filter failed: %v", err)
		return
	}
	_ = s.api.setParam(newHandle, windivertParamQueueLength, 8192)
	_ = s.api.setParam(newHandle, windivertParamQueueSize, 8*1024*1024)
	_ = s.api.setParam(newHandle, windivertParamQueueTime, 2000)

	oldHandle := s.networkHandle
	s.networkHandle = newHandle
	s.networkFilter = filter
	s.networkMu.Unlock()

	if oldHandle != 0 {
		_ = s.api.close(oldHandle)
	}
}

func (s *WindowsService) buildNetworkFilter() string {
	s.mu.RLock()
	connections := make([]*redirectConnection, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.RUnlock()

	if len(connections) == 0 {
		return networkIdleFilter
	}

	parts := make([]string, 0, len(connections)*2)
	for _, conn := range connections {
		if conn == nil {
			continue
		}
		parts = append(parts,
			fmt.Sprintf("(tcp.SrcPort == %d and tcp.DstPort == %d)", conn.localPort, conn.remotePort),
			fmt.Sprintf("(tcp.SrcPort == %d and tcp.DstPort == %d)", conn.redirectPort, conn.remotePort),
		)
	}
	if len(parts) == 0 {
		return networkIdleFilter
	}
	return "tcp and ip and !loopback and (" + strings.Join(parts, " or ") + ")"
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

func (s *WindowsService) registerConnection(proc processInfo, query string, profile resolvedTunAppProfile, localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) error {
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
		query:        query,
		profileID:    profile.ID,
		profileName:  profile.Name,
		routingMode:  profile.RoutingMode,
		ifIdx:        interfaceIndexForIP(localIP),
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
	s.refreshNetworkFilter()

	atomic.AddUint64(&s.redirectPrepared, 1)
	s.logf("redirect prepared query=%s pid=%d %s:%d -> %s:%d via local-port=%d", query, proc.pid, conn.localAddr, conn.localPort, conn.remoteAddr, conn.remotePort, conn.redirectPort)
	s.persistRuntimeSnapshot()
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
	if conn != nil {
		s.refreshNetworkFilter()
	}
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
	if len(stale) > 0 {
		s.refreshNetworkFilter()
	}
}

func (s *WindowsService) serveReflectedConnection(rc *redirectConnection) {
	defer s.wg.Done()
	defer rc.listener.Close()

	tcpListener, ok := rc.listener.(*net.TCPListener)
	if ok {
		_ = tcpListener.SetDeadline(time.Now().Add(30 * time.Second))
	}
	s.logf("waiting reflected connection pid=%d local=%s:%d redirect-port=%d remote=%s:%d", rc.processID, rc.localAddr, rc.localPort, rc.redirectPort, rc.remoteAddr, rc.remotePort)
	appConn, err := rc.listener.Accept()
	if err != nil {
		if s.isRunning() && !errors.Is(err, net.ErrClosed) {
			s.logf("accept reflected connection failed: %v", err)
		}
		return
	}
	defer appConn.Close()
	rc.accepted.Store(true)
	atomic.AddUint64(&s.acceptCount, 1)
	s.logf("reflected connection accepted pid=%d proc=%s remote=%s:%d", rc.processID, rc.processPath, rc.remoteAddr, rc.remotePort)
	s.persistRuntimeSnapshot()

	prefix, sniffErr := captureInitialPayload(appConn, 16*1024, 1200*time.Millisecond)
	if sniffErr != nil && !errors.Is(sniffErr, io.EOF) {
		s.logf("capture initial payload failed pid=%d remote=%s:%d: %v", rc.processID, rc.remoteAddr, rc.remotePort, sniffErr)
	}
	host, source := detectHostFromInitialPayload(prefix)
	decision := decideAppRoute(host, rc.remoteAddr, s.options.Rules, rc.routingMode)
	s.logf(
		"app route decided pid=%d profile=%s proc=%s remote=%s:%d sniff-host=%q sniff-source=%s basis=%s matched=%s,%s target=%s mode=%s",
		rc.processID,
		rc.profileName,
		rc.processName,
		rc.remoteAddr,
		rc.remotePort,
		host,
		source,
		decision.Basis,
		decision.Matched.Type,
		decision.Matched.Value,
		decision.Rule.Target,
		rc.routingMode,
	)
	if decision.Rule.Target == model.RuleTargetReject {
		s.logf("connection rejected pid=%d proc=%s remote=%s:%d matched=%s,%s", rc.processID, rc.processName, rc.remoteAddr, rc.remotePort, decision.Matched.Type, decision.Matched.Value)
		return
	}

	upstreamCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	upstreamConn, err := s.dialByTarget(upstreamCtx, decision.Rule.Target, net.JoinHostPort(rc.remoteAddr.String(), fmt.Sprintf("%d", rc.remotePort)))
	if err != nil {
		atomic.AddUint64(&s.upstreamDialFailed, 1)
		s.recordUpstreamError(err)
		s.logf("dial target failed for %s:%d target=%s: %v", rc.remoteAddr, rc.remotePort, decision.Rule.Target, err)
		s.persistRuntimeSnapshot()
		return
	}
	defer upstreamConn.Close()

	atomic.AddUint64(&s.tunnelEstablished, 1)
	s.logf("transparent tunnel established pid=%d %s -> %s:%d target=%s", rc.processID, rc.processName, rc.remoteAddr, rc.remotePort, decision.Rule.Target)
	s.persistRuntimeSnapshot()
	pipe := func(dst net.Conn, prefix []byte, src net.Conn) {
		if len(prefix) > 0 {
			if _, err := dst.Write(prefix); err != nil {
				return
			}
		}
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
		pipe(upstreamConn, prefix, appConn)
	}()
	go func() {
		defer wg.Done()
		pipe(appConn, nil, upstreamConn)
	}()
	wg.Wait()
	time.AfterFunc(15*time.Second, func() {
		s.unregisterConnection(rc.localPort)
	})
}

func captureInitialPayload(conn net.Conn, limit int, timeout time.Duration) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 0, limit)
	tmp := make([]byte, 4096)
	for len(buf) < limit {
		chunk := tmp
		if remain := limit - len(buf); remain < len(chunk) {
			chunk = chunk[:remain]
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if host, _ := detectHostFromInitialPayload(buf); host != "" {
				return buf, nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return buf, nil
			}
			if errors.Is(err, io.EOF) {
				return buf, err
			}
			return buf, err
		}
	}
	return buf, nil
}

func (s *WindowsService) dialUpstream(ctx context.Context, destination string) (net.Conn, error) {
	upstreamAddr := strings.TrimSpace(s.options.UpstreamProxyAddr)
	upstreamType := strings.ToLower(strings.TrimSpace(s.options.UpstreamProxyType))
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

func (s *WindowsService) dialByTarget(ctx context.Context, target model.RuleTarget, destination string) (net.Conn, error) {
	if target == model.RuleTargetDirect {
		dialer, err := s.buildDirectDialer()
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, "tcp", destination)
	}
	return s.dialUpstream(ctx, destination)
}

func (s *WindowsService) buildDirectDialer() (*net.Dialer, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	iface := strings.TrimSpace(s.options.DirectInterface)
	if iface == "" {
		return dialer, nil
	}
	ip, err := netadapter.LookupIPv4(iface)
	if err != nil {
		fallbackIP, _, fallbackErr := netadapter.LookupFallbackIPv4(iface)
		if fallbackErr != nil {
			return nil, err
		}
		ip = fallbackIP
	}
	dialer.LocalAddr = &net.TCPAddr{IP: ip}
	return dialer, nil
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
	return procmatch.MatchProcess(proc.name, proc.path, queries)
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

func resolveTunAppProfiles(profiles []model.TunAppProfile, includedApps []string) []resolvedTunAppProfile {
	if len(profiles) == 0 {
		queries := normalizeApps(includedApps)
		if len(queries) == 0 {
			return nil
		}
		return []resolvedTunAppProfile{{
			Name:        "Legacy Applications",
			RoutingMode: model.TunAppRoutingRulesProxyFallback,
			Queries:     queries,
		}}
	}

	out := make([]resolvedTunAppProfile, 0, len(profiles))
	for _, profile := range profiles {
		queries := normalizeApps(profile.Queries)
		if len(queries) == 0 || !profile.Enabled || profile.BypassTransparentProxy {
			continue
		}
		mode := profile.RoutingMode
		if mode == "" {
			mode = model.TunAppRoutingRulesProxyFallback
		}
		out = append(out, resolvedTunAppProfile{
			ID:          strings.TrimSpace(profile.ID),
			Name:        strings.TrimSpace(profile.Name),
			RoutingMode: mode,
			Remark:      strings.TrimSpace(profile.Remark),
			Queries:     queries,
		})
	}
	return out
}

func flattenResolvedTunQueries(profiles []resolvedTunAppProfile) []string {
	values := make([]string, 0, len(profiles)*2)
	for _, profile := range profiles {
		values = append(values, profile.Queries...)
	}
	return normalizeApps(values)
}

func buildResolvedTunQueryMap(profiles []resolvedTunAppProfile) map[string]resolvedTunAppProfile {
	out := make(map[string]resolvedTunAppProfile, len(profiles)*2)
	for _, profile := range profiles {
		for _, query := range profile.Queries {
			out[strings.ToLower(strings.TrimSpace(query))] = profile
		}
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

func (s *WindowsService) shouldBypassTransparentConnect(remoteIP net.IP, remotePort uint16) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s.options.UpstreamProxyAddr))
	if err != nil {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || uint16(parsedPort) != remotePort {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return remoteIP.IsLoopback()
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.Equal(remoteIP)
	}
	resolveCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(remoteIP) {
			return true
		}
	}
	return false
}

func ipv4FromMapped(words [4]uint32) net.IP {
	// WinDivert exposes SOCKET-layer IPv4 addresses as IPv4-mapped IPv6 values in
	// host byte order, with the low 32 bits first on little-endian Windows hosts:
	// [ ipv4, 0x0000ffff, 0x00000000, 0x00000000 ].
	if words[1] != 0x0000ffff || words[2] != 0 || words[3] != 0 {
		return nil
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], words[0])
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
}

func ensureWinDivertRuntime(runtimeDir string) (string, error) {
	// If runtimeDir already contains the runtime files, use them.
	ok := true
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		if _, err := os.Stat(filepath.Join(runtimeDir, name)); err != nil {
			ok = false
			break
		}
	}
	if ok {
		return filepath.Join(runtimeDir, "WinDivert.dll"), nil
	}

	sourceDir, err := winDivertRuntimeDir()
	if err != nil {
		return "", err
	}
	if samePath(sourceDir, runtimeDir) {
		return filepath.Join(runtimeDir, "WinDivert.dll"), nil
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

func winDivertRuntimeDir() (string, error) {
	dir, err := prmfs.TunRuntimeDir()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return "", fmt.Errorf("未找到 WinDivert 运行文件，请确认 %s 下已放置 %s", dir, name)
		}
	}
	return dir, nil
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
	return winDivertRuntimeDir()
}

func samePath(left, right string) bool {
	return filepath.Clean(strings.ToLower(left)) == filepath.Clean(strings.ToLower(right))
}

func interfaceIndexForIP(target net.IP) uint32 {
	target = target.To4()
	if target == nil {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip = ip.To4()
			if ip != nil && ip.Equal(target) {
				return uint32(iface.Index)
			}
		}
	}
	return 0
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

func (s *WindowsService) profileForQuery(query string) resolvedTunAppProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if profile, ok := s.queryMap[strings.ToLower(strings.TrimSpace(query))]; ok {
		return profile
	}
	return resolvedTunAppProfile{
		Name:        query,
		RoutingMode: model.TunAppRoutingRulesProxyFallback,
		Queries:     []string{query},
	}
}

func (s *WindowsService) ensureUDPBlock(processPath string) error {
	key := strings.ToLower(strings.TrimSpace(processPath))
	if key == "" {
		return nil
	}
	s.mu.Lock()
	_, exists := s.udpBlocked[key]
	if exists {
		s.mu.Unlock()
		return nil
	}
	if s.udpBlocking == nil {
		s.udpBlocking = map[string]*udpBlockCall{}
	}
	if call, ok := s.udpBlocking[key]; ok {
		s.mu.Unlock()
		<-call.done
		return call.err
	}
	call := &udpBlockCall{done: make(chan struct{})}
	s.udpBlocking[key] = call
	s.mu.Unlock()

	if _, err := runPowerShell(addTransparentUDPBlockScript(processPath)); err != nil {
		s.mu.Lock()
		call.err = err
		delete(s.udpBlocking, key)
		close(call.done)
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	if s.udpBlocked != nil {
		s.udpBlocked[key] = struct{}{}
	}
	delete(s.udpBlocking, key)
	close(call.done)
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

func (s *WindowsService) recordSocketError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSocketError = err.Error()
}

func (s *WindowsService) recordUpstreamError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUpstreamError = err.Error()
}

func (s *WindowsService) recordMatchedProcess(proc processInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastMatchedProcess = proc.path
}

func (s *WindowsService) persistRuntimeSnapshot() {
	s.mu.RLock()
	snapshot := runtimeSnapshot{
		GeneratedAt:           time.Now().Format(time.RFC3339),
		Running:               s.running,
		Message:               s.lastMessage,
		LogPath:               s.logPath,
		DriverPath:            s.driverPath,
		Options:               s.options,
		Queries:               append([]string(nil), s.queries...),
		SocketConnectEvents:   atomic.LoadUint64(&s.socketConnectEvents),
		MatchedConnects:       atomic.LoadUint64(&s.matchedConnects),
		RedirectPreparedCount: atomic.LoadUint64(&s.redirectPrepared),
		AcceptCount:           atomic.LoadUint64(&s.acceptCount),
		UpstreamDialFailures:  atomic.LoadUint64(&s.upstreamDialFailed),
		TunnelEstablished:     atomic.LoadUint64(&s.tunnelEstablished),
		ForwardReflected:      atomic.LoadUint64(&s.forwardReflected),
		ReverseReflected:      atomic.LoadUint64(&s.reverseReflected),
		LastMatchedProcess:    s.lastMatchedProcess,
		LastSocketError:       s.lastSocketError,
		LastUpstreamError:     s.lastUpstreamError,
	}
	configPath := s.configPath
	s.mu.RUnlock()

	if configPath == "" {
		return
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		s.logf("persist runtime snapshot marshal failed: %v", err)
		return
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		s.logf("persist runtime snapshot write failed: %v", err)
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
	_, err := runPowerShell("$ErrorActionPreference = 'Stop'\n" +
		"$group = '" + psLiteral(transparentFWGroup) + "'\n" +
		"$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $group })\n" +
		"if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule -ErrorAction Stop | Out-Null }\n")
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
	b.WriteString("$exists = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $group -and $_.DisplayName -eq $display })\n")
	b.WriteString("if (-not $exists) {\n")
	b.WriteString("  New-NetFirewallRule -DisplayName $display -Group $group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $program -Protocol UDP | Out-Null\n")
	b.WriteString("}\n")
	return b.String()
}

func ensureTransparentTCPAllow() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	_, err = runPowerShell(addTransparentTCPAllowScript(exePath))
	return err
}

func addTransparentTCPAllowScript(programPath string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$group = '")
	b.WriteString(psLiteral(transparentFWGroup))
	b.WriteString("'\n")
	b.WriteString("$program = (Resolve-Path -LiteralPath '")
	b.WriteString(psLiteral(programPath))
	b.WriteString("').Path\n")
	b.WriteString("$display = 'Transparent TCP Allow - ' + [System.IO.Path]::GetFileName($program)\n")
	b.WriteString("$exists = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Group -eq $group -and $_.DisplayName -eq $display })\n")
	b.WriteString("if ($exists.Count -eq 0) {\n")
	b.WriteString("  New-NetFirewallRule -DisplayName $display -Group $group -Direction Inbound -Action Allow -Enabled True -Profile Any -Program $program -Protocol TCP | Out-Null\n")
	b.WriteString("}\n")
	return b.String()
}

func psLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func runPowerShell(script string) (string, error) {
	return winps.Run("透明接管防火墙规则", script, 20*time.Second)
}
