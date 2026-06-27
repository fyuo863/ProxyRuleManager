package proxyguard

import "proxy-rule-manager/internal/model"

type Service interface {
	Reconcile(cfg model.AppConfig) error
	Status() model.ProxyGuardRuntimeStatus
}
