//go:build windows

package tun

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windivertLayerNetwork = 0
	windivertLayerSocket  = 3

	windivertEventSocketConnect = 4
	windivertEventSocketClose   = 7

	windivertFlagSniff    = 0x0001
	windivertFlagRecvOnly = 0x0004

	windivertParamQueueLength = 0
	windivertParamQueueTime   = 1
	windivertParamQueueSize   = 2
)

type winDivertAPI struct {
	dll               *windows.DLL
	openProc          *windows.Proc
	recvProc          *windows.Proc
	sendProc          *windows.Proc
	closeProc         *windows.Proc
	setParamProc      *windows.Proc
	calcChecksumsProc *windows.Proc
}

type winDivertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}

type winDivertDataNetwork struct {
	IfIdx    uint32
	SubIfIdx uint32
}

type winDivertDataSocket struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [3]byte
}

func loadWinDivertAPI(dllPath string) (*winDivertAPI, error) {
	dll, err := windows.LoadDLL(dllPath)
	if err != nil {
		return nil, err
	}
	api := &winDivertAPI{
		dll:               dll,
		openProc:          dll.MustFindProc("WinDivertOpen"),
		recvProc:          dll.MustFindProc("WinDivertRecv"),
		sendProc:          dll.MustFindProc("WinDivertSend"),
		closeProc:         dll.MustFindProc("WinDivertClose"),
		setParamProc:      dll.MustFindProc("WinDivertSetParam"),
		calcChecksumsProc: dll.MustFindProc("WinDivertHelperCalcChecksums"),
	}
	return api, nil
}

func (api *winDivertAPI) open(filter string, layer uint32, priority int16, flags uint64) (windows.Handle, error) {
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := api.openProc.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(layer),
		uintptr(uint16(priority)),
		uintptr(flags),
	)
	if handle == uintptr(windows.InvalidHandle) {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, windows.GetLastError()
	}
	return windows.Handle(handle), nil
}

func (api *winDivertAPI) recv(handle windows.Handle, packet []byte, addr *winDivertAddress) (int, error) {
	var packetPtr uintptr
	if len(packet) > 0 {
		packetPtr = uintptr(unsafe.Pointer(&packet[0]))
	}
	var recvLen uint32
	r1, _, callErr := api.recvProc.Call(
		uintptr(handle),
		packetPtr,
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, windows.GetLastError()
	}
	return int(recvLen), nil
}

func (api *winDivertAPI) send(handle windows.Handle, packet []byte, addr *winDivertAddress) error {
	var packetPtr uintptr
	if len(packet) > 0 {
		packetPtr = uintptr(unsafe.Pointer(&packet[0]))
	}
	r1, _, callErr := api.sendProc.Call(
		uintptr(handle),
		packetPtr,
		uintptr(uint32(len(packet))),
		0,
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return windows.GetLastError()
	}
	return nil
}

func (api *winDivertAPI) close(handle windows.Handle) error {
	r1, _, callErr := api.closeProc.Call(uintptr(handle))
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return windows.GetLastError()
	}
	return nil
}

func (api *winDivertAPI) setParam(handle windows.Handle, param uint32, value uint64) error {
	r1, _, callErr := api.setParamProc.Call(
		uintptr(handle),
		uintptr(param),
		uintptr(value),
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return windows.GetLastError()
	}
	return nil
}

func (api *winDivertAPI) calcChecksums(packet []byte, addr *winDivertAddress) error {
	if len(packet) == 0 {
		return nil
	}
	r1, _, callErr := api.calcChecksumsProc.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return fmt.Errorf("WinDivertHelperCalcChecksums failed: %w", windows.GetLastError())
	}
	return nil
}

func (a *winDivertAddress) event() uint8 {
	return uint8((a.Flags >> 8) & 0xFF)
}

func (a *winDivertAddress) outbound() bool {
	return a.Flags&(1<<17) != 0
}

func (a *winDivertAddress) setOutbound(value bool) {
	if value {
		a.Flags |= 1 << 17
		return
	}
	a.Flags &^= 1 << 17
}

func (a *winDivertAddress) network() *winDivertDataNetwork {
	return (*winDivertDataNetwork)(unsafe.Pointer(&a.Data[0]))
}

func (a *winDivertAddress) socket() *winDivertDataSocket {
	return (*winDivertDataSocket)(unsafe.Pointer(&a.Data[0]))
}
