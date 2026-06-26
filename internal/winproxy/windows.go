//go:build windows

package winproxy

import (
	"syscall"

	"golang.org/x/sys/windows/registry"

	"proxy-rule-manager/internal/model"
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func ReadCurrentConfig() (model.WindowsProxyConfig, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return model.WindowsProxyConfig{}, err
	}
	defer key.Close()

	autoURL, _, _ := key.GetStringValue("AutoConfigURL")
	proxyServer, _, _ := key.GetStringValue("ProxyServer")
	proxyEnableVal, _, _ := key.GetIntegerValue("ProxyEnable")

	return model.WindowsProxyConfig{
		AutoConfigURL: autoURL,
		ProxyEnable:   proxyEnableVal != 0,
		ProxyServer:   proxyServer,
	}, nil
}

func ApplyPAC(url string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetStringValue("AutoConfigURL", url); err != nil {
		return err
	}
	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}
	if err := key.DeleteValue("ProxyServer"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return refresh()
}

func Restore(config model.WindowsProxyConfig) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if config.AutoConfigURL == "" {
		if err := key.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
			return err
		}
	} else if err := key.SetStringValue("AutoConfigURL", config.AutoConfigURL); err != nil {
		return err
	}

	if err := key.SetDWordValue("ProxyEnable", boolToDWORD(config.ProxyEnable)); err != nil {
		return err
	}

	if config.ProxyServer == "" {
		if err := key.DeleteValue("ProxyServer"); err != nil && err != registry.ErrNotExist {
			return err
		}
	} else if err := key.SetStringValue("ProxyServer", config.ProxyServer); err != nil {
		return err
	}
	return refresh()
}

func refresh() error {
	if _, _, err := procInternetSetOptionW.Call(0, uintptr(internetOptionSettingsChanged), 0, 0); err != syscall.Errno(0) {
		return err
	}
	if _, _, err := procInternetSetOptionW.Call(0, uintptr(internetOptionRefresh), 0, 0); err != syscall.Errno(0) {
		return err
	}
	return nil
}

func boolToDWORD(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}
