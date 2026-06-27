//go:build !windows

package proxyguard

import "proxy-rule-manager/internal/model"

type StubService struct {
	status model.ProxyGuardRuntimeStatus
}

func NewService() Service {
	return &StubService{
		status: model.ProxyGuardRuntimeStatus{Message: "代理进程出口限制当前仅支持 Windows"},
	}
}

func (s *StubService) Reconcile(cfg model.AppConfig) error {
	if cfg.ProxyGuardEnabled {
		s.status = model.ProxyGuardRuntimeStatus{Message: "代理进程出口限制当前仅支持 Windows"}
		return nil
	}
	s.status = model.ProxyGuardRuntimeStatus{Message: "未启用代理进程出口限制"}
	return nil
}

func (s *StubService) Status() model.ProxyGuardRuntimeStatus {
	return s.status
}
