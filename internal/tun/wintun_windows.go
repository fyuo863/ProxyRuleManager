//go:build windows

package tun

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wintunAdapter uintptr
type wintunSession uintptr

type wintunAPI struct {
	dll               *windows.DLL
	openAdapterProc   *windows.Proc
	createAdapterProc *windows.Proc
	closeAdapterProc  *windows.Proc
	startSessionProc  *windows.Proc
	endSessionProc    *windows.Proc
	readWaitEventProc *windows.Proc
	receivePacketProc *windows.Proc
	releasePacketProc *windows.Proc
}

func loadWintunAPI(path string) (*wintunAPI, error) {
	dll, err := windows.LoadDLL(path)
	if err != nil {
		return nil, err
	}

	api := &wintunAPI{dll: dll}
	if api.openAdapterProc, err = dll.FindProc("WintunOpenAdapter"); err != nil {
		return nil, err
	}
	if api.createAdapterProc, err = dll.FindProc("WintunCreateAdapter"); err != nil {
		return nil, err
	}
	if api.closeAdapterProc, err = dll.FindProc("WintunCloseAdapter"); err != nil {
		return nil, err
	}
	if api.startSessionProc, err = dll.FindProc("WintunStartSession"); err != nil {
		return nil, err
	}
	if api.endSessionProc, err = dll.FindProc("WintunEndSession"); err != nil {
		return nil, err
	}
	if api.readWaitEventProc, err = dll.FindProc("WintunGetReadWaitEvent"); err != nil {
		return nil, err
	}
	if api.receivePacketProc, err = dll.FindProc("WintunReceivePacket"); err != nil {
		return nil, err
	}
	if api.releasePacketProc, err = dll.FindProc("WintunReleaseReceivePacket"); err != nil {
		return nil, err
	}
	return api, nil
}

func (api *wintunAPI) openOrCreateAdapter(name string) (wintunAdapter, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	r1, _, callErr := api.openAdapterProc.Call(uintptr(unsafe.Pointer(namePtr)))
	if r1 != 0 {
		return wintunAdapter(r1), nil
	}
	if errno, ok := callErr.(windows.Errno); ok && errno != windows.ERROR_FILE_NOT_FOUND {
		return 0, callErr
	}

	tunnelType, err := windows.UTF16PtrFromString("ProxyRuleManager")
	if err != nil {
		return 0, err
	}
	r1, _, callErr = api.createAdapterProc.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(tunnelType)),
		0,
	)
	if r1 == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return 0, fmt.Errorf("创建 Wintun 适配器失败: %w", callErr)
	}
	return wintunAdapter(r1), nil
}

func (api *wintunAPI) closeAdapter(adapter wintunAdapter) {
	if adapter == 0 {
		return
	}
	_, _, _ = api.closeAdapterProc.Call(uintptr(adapter))
}

func (api *wintunAPI) startSession(adapter wintunAdapter, capacity uint32) (wintunSession, error) {
	r1, _, callErr := api.startSessionProc.Call(uintptr(adapter), uintptr(capacity))
	if r1 == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return 0, fmt.Errorf("启动 Wintun 会话失败: %w", callErr)
	}
	return wintunSession(r1), nil
}

func (api *wintunAPI) endSession(session wintunSession) {
	if session == 0 {
		return
	}
	_, _, _ = api.endSessionProc.Call(uintptr(session))
}

func (api *wintunAPI) readWaitEvent(session wintunSession) (windows.Handle, error) {
	r1, _, callErr := api.readWaitEventProc.Call(uintptr(session))
	if r1 == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return 0, fmt.Errorf("获取 Wintun 读事件失败: %w", callErr)
	}
	return windows.Handle(r1), nil
}

func (api *wintunAPI) receivePacket(session wintunSession) (uintptr, uint32, error) {
	var size uint32
	r1, _, callErr := api.receivePacketProc.Call(uintptr(session), uintptr(unsafe.Pointer(&size)))
	if r1 == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_NO_MORE_ITEMS
		}
		return 0, 0, callErr
	}
	return r1, size, nil
}

func (api *wintunAPI) releaseReceivePacket(session wintunSession, packet uintptr) {
	if packet == 0 {
		return
	}
	_, _, _ = api.releasePacketProc.Call(uintptr(session), packet)
}
