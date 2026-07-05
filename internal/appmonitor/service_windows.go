//go:build windows

package appmonitor

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/procmatch"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	anySize             = 1
)

type WindowsService struct {
	mu        sync.RWMutex
	addLog    func(model.TrafficLog)
	updateLog func(string, func(*model.TrafficLog))
	routeHint RouteHintFunc
	included  []string
	snapshot  Snapshot
	tracked   map[string]trackedConnection
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

type trackedConnection struct {
	logID     string
	startedAt time.Time
	lastSeen  time.Time
}

type processInfo struct {
	pid  uint32
	name string
	path string
}

type tcpConnection struct {
	pid        uint32
	localAddr  string
	localPort  uint16
	remoteAddr string
	remotePort uint16
	status     string
	family     string
}

type mibTCPRowOwnerPID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}

type mibTCPTableOwnerPID struct {
	DwNumEntries uint32
	Table        [anySize]mibTCPRowOwnerPID
}

type mibTCP6RowOwnerPID struct {
	UcLocalAddr     [16]byte
	DwLocalScopeID  uint32
	DwLocalPort     uint32
	UcRemoteAddr    [16]byte
	DwRemoteScopeID uint32
	DwRemotePort    uint32
	DwState         uint32
	DwOwningPid     uint32
}

type mibTCP6TableOwnerPID struct {
	DwNumEntries uint32
	Table        [anySize]mibTCP6RowOwnerPID
}

var tcpStates = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN-SENT",
	4:  "SYN-RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN-WAIT-1",
	7:  "FIN-WAIT-2",
	8:  "CLOSE-WAIT",
	9:  "CLOSING",
	10: "LAST-ACK",
	11: "TIME-WAIT",
	12: "DELETE-TCB",
}

func NewService(addLog func(model.TrafficLog), updateLog func(string, func(*model.TrafficLog)), routeHint RouteHintFunc) Service {
	return &WindowsService{
		addLog:    addLog,
		updateLog: updateLog,
		routeHint: routeHint,
		tracked:   map[string]trackedConnection{},
	}
}

func (s *WindowsService) Start(includedApps []string) {
	s.mu.Lock()
	s.included = normalizeQueries(includedApps)
	if s.stopCh != nil {
		s.mu.Unlock()
		return
	}
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pollLoop()
	}()
}

func (s *WindowsService) UpdateIncludedApps(includedApps []string) {
	s.mu.Lock()
	s.included = normalizeQueries(includedApps)
	s.mu.Unlock()
}

func (s *WindowsService) Stop() {
	s.mu.Lock()
	stopCh := s.stopCh
	s.stopCh = nil
	s.mu.Unlock()
	if stopCh != nil {
		close(stopCh)
	}
	s.wg.Wait()
	s.finishStaleConnections(nil)
}

func (s *WindowsService) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]model.ManagedAppStatus, len(s.snapshot.ManagedApps))
	copy(items, s.snapshot.ManagedApps)
	return Snapshot{
		ManagedApps:            items,
		ManagedProcessCount:    s.snapshot.ManagedProcessCount,
		ManagedConnectionCount: s.snapshot.ManagedConnectionCount,
	}
}

func (s *WindowsService) pollLoop() {
	s.refresh()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		s.mu.RLock()
		stopCh := s.stopCh
		s.mu.RUnlock()

		select {
		case <-ticker.C:
			s.refresh()
		case <-stopCh:
			return
		}
	}
}

func (s *WindowsService) refresh() {
	queries := s.currentQueries()
	if len(queries) == 0 {
		s.mu.Lock()
		s.snapshot = Snapshot{}
		s.mu.Unlock()
		s.finishStaleConnections(map[string]connectionDetail{})
		return
	}

	processes, err := snapshotProcesses()
	if err != nil {
		return
	}
	matchedApps, pidLookup := matchProcesses(queries, processes)
	connections, err := listTCPConnections()
	if err != nil {
		return
	}

	current := map[string]connectionDetail{}
	activeConnections := 0
	for _, conn := range connections {
		proc, ok := pidLookup[conn.pid]
		if !ok {
			continue
		}
		if conn.remotePort == 0 || conn.remoteAddr == "" || conn.remoteAddr == "0.0.0.0" || conn.remoteAddr == "::" {
			continue
		}
		if conn.status == "LISTEN" {
			continue
		}
		activeConnections++
		app := matchedApps[proc.pid]
		app.ActiveConnections++
		matchedApps[proc.pid] = app
		detail := connectionDetail{process: proc, app: app, conn: conn}
		current[connectionKey(detail)] = detail
	}

	managedApps := collapseManagedApps(queries, matchedApps)
	s.mu.Lock()
	s.snapshot = Snapshot{
		ManagedApps:            managedApps,
		ManagedProcessCount:    len(matchedApps),
		ManagedConnectionCount: activeConnections,
	}
	s.mu.Unlock()

	s.syncConnections(current)
}

type connectionDetail struct {
	process processInfo
	app     model.ManagedAppStatus
	conn    tcpConnection
}

func (s *WindowsService) syncConnections(current map[string]connectionDetail) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, detail := range current {
		tracked, exists := s.tracked[key]
		if exists {
			tracked.lastSeen = now
			s.tracked[key] = tracked
			s.updateLog(tracked.logID, func(item *model.TrafficLog) {
				item.DurationMs = time.Since(tracked.startedAt).Milliseconds()
				item.ProcessName = detail.process.name
				item.ProcessPath = detail.process.path
				item.ProcessID = detail.process.pid
				item.Path = s.describeManagedPath(detail.process)
			})
			continue
		}

		target, path := s.routeHint(detail.process.name, detail.process.path)
		logID := uuid.NewString()
		s.addLog(model.TrafficLog{
			ID:               logID,
			Time:             now.Format(time.RFC3339),
			Source:           "process",
			Host:             detail.conn.remoteAddr,
			Port:             fmt.Sprintf("%d", detail.conn.remotePort),
			Protocol:         "APP/" + detail.conn.family,
			ProcessID:        detail.process.pid,
			ProcessName:      detail.process.name,
			ProcessPath:      detail.process.path,
			MatchedRuleType:  model.RuleTypeMatch,
			MatchedRuleValue: "APP:" + detail.app.Query,
			MatchedRuleIndex: -1,
			Target:           target,
			Path:             path,
			Status:           model.TrafficStatusActive,
		})
		s.tracked[key] = trackedConnection{
			logID:     logID,
			startedAt: now,
			lastSeen:  now,
		}
	}

	for key, tracked := range s.tracked {
		if _, ok := current[key]; ok {
			continue
		}
		s.updateLog(tracked.logID, func(item *model.TrafficLog) {
			item.DurationMs = time.Since(tracked.startedAt).Milliseconds()
			item.Status = model.TrafficStatusClosed
		})
		delete(s.tracked, key)
	}
}

func (s *WindowsService) finishStaleConnections(current map[string]connectionDetail) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, tracked := range s.tracked {
		if current != nil {
			if _, ok := current[key]; ok {
				continue
			}
		}
		s.updateLog(tracked.logID, func(item *model.TrafficLog) {
			item.DurationMs = time.Since(tracked.startedAt).Milliseconds()
			item.Status = model.TrafficStatusClosed
		})
		delete(s.tracked, key)
	}
	_ = now
}

func (s *WindowsService) currentQueries() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.included))
	copy(out, s.included)
	return out
}

func (s *WindowsService) describeManagedPath(proc processInfo) string {
	target, path := s.routeHint(proc.name, proc.path)
	if path != "" {
		return path
	}
	if target == model.RuleTargetProxy {
		return fmt.Sprintf("进程识别 -> %s -> TUN 实验数据面", proc.name)
	}
	return fmt.Sprintf("进程识别 -> %s", proc.name)
}

func normalizeQueries(values []string) []string {
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

func snapshotProcesses() (map[uint32]processInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	out := map[uint32]processInfo{}
	for {
		pid := entry.ProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])
		out[pid] = processInfo{
			pid:  pid,
			name: name,
			path: queryProcessPath(pid),
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return out, nil
		}
	}
	return out, nil
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

func matchProcesses(queries []string, processes map[uint32]processInfo) (map[uint32]model.ManagedAppStatus, map[uint32]processInfo) {
	matchedApps := map[uint32]model.ManagedAppStatus{}
	pidLookup := map[uint32]processInfo{}
	for _, proc := range processes {
		query, ok := procmatch.MatchProcess(proc.name, proc.path, queries)
		if !ok {
			continue
		}
		pidLookup[proc.pid] = proc
		matchedApps[proc.pid] = model.ManagedAppStatus{
			Query:             query,
			Name:              proc.name,
			Path:              proc.path,
			Running:           true,
			PIDCount:          1,
			ActiveConnections: 0,
		}
	}
	return matchedApps, pidLookup
}

func matchProcessQuery(proc processInfo, queries []string) (string, bool) {
	return procmatch.MatchProcess(proc.name, proc.path, queries)
}

func collapseManagedApps(queries []string, matched map[uint32]model.ManagedAppStatus) []model.ManagedAppStatus {
	index := map[string]*model.ManagedAppStatus{}
	for _, query := range queries {
		item := model.ManagedAppStatus{Query: query}
		index[strings.ToLower(query)] = &item
	}
	for _, app := range matched {
		key := strings.ToLower(app.Query)
		target := index[key]
		if target == nil {
			copyItem := model.ManagedAppStatus{Query: app.Query}
			target = &copyItem
			index[key] = target
		}
		target.Running = true
		target.PIDCount++
		target.ActiveConnections += app.ActiveConnections
		if target.Name == "" {
			target.Name = app.Name
		}
		if target.Path == "" {
			target.Path = app.Path
		}
	}

	out := make([]model.ManagedAppStatus, 0, len(queries))
	for _, query := range queries {
		item := index[strings.ToLower(query)]
		if item == nil {
			item = &model.ManagedAppStatus{Query: query}
		}
		out = append(out, *item)
	}
	return out
}

func listTCPConnections() ([]tcpConnection, error) {
	items := make([]tcpConnection, 0, 64)
	v4, err := queryTCPTable(syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	items = append(items, v4...)
	v6, err := queryTCPTable(syscall.AF_INET6)
	if err == nil {
		items = append(items, v6...)
	}
	return items, nil
}

func queryTCPTable(af uint32) ([]tcpConnection, error) {
	var size uint32
	r1, _, callErr := procGetExtendedTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(af),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if r1 != 0 && windows.Errno(r1) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, callErr
	}

	buf := make([]byte, size)
	r1, _, callErr = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(af),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if r1 != 0 {
		return nil, callErr
	}

	if af == syscall.AF_INET {
		table := (*mibTCPTableOwnerPID)(unsafe.Pointer(&buf[0]))
		rows := unsafe.Slice(&table.Table[0], int(table.DwNumEntries))
		out := make([]tcpConnection, 0, len(rows))
		for _, row := range rows {
			out = append(out, tcpConnection{
				pid:        row.DwOwningPid,
				localAddr:  parseIPv4(row.DwLocalAddr),
				localPort:  decodePort(row.DwLocalPort),
				remoteAddr: parseIPv4(row.DwRemoteAddr),
				remotePort: decodePort(row.DwRemotePort),
				status:     tcpStates[row.DwState],
				family:     "TCP4",
			})
		}
		return out, nil
	}

	table := (*mibTCP6TableOwnerPID)(unsafe.Pointer(&buf[0]))
	rows := unsafe.Slice(&table.Table[0], int(table.DwNumEntries))
	out := make([]tcpConnection, 0, len(rows))
	for _, row := range rows {
		out = append(out, tcpConnection{
			pid:        row.DwOwningPid,
			localAddr:  net.IP(row.UcLocalAddr[:]).String(),
			localPort:  decodePort(row.DwLocalPort),
			remoteAddr: net.IP(row.UcRemoteAddr[:]).String(),
			remotePort: decodePort(row.DwRemotePort),
			status:     tcpStates[row.DwState],
			family:     "TCP6",
		})
	}
	return out, nil
}

func decodePort(value uint32) uint16 {
	return syscall.Ntohs(uint16(value))
}

func parseIPv4(value uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", value&255, value>>8&255, value>>16&255, value>>24&255)
}

func connectionKey(detail connectionDetail) string {
	return fmt.Sprintf("%d|%s|%d|%s|%d|%s", detail.process.pid, detail.conn.localAddr, detail.conn.localPort, detail.conn.remoteAddr, detail.conn.remotePort, detail.conn.family)
}

func baseName(value string) string {
	value = strings.ReplaceAll(value, "/", "\\")
	parts := strings.Split(value, "\\")
	return parts[len(parts)-1]
}
