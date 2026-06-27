package appmonitor

import "proxy-rule-manager/internal/model"

type Snapshot struct {
	ManagedApps            []model.ManagedAppStatus
	ManagedProcessCount    int
	ManagedConnectionCount int
}

type RouteHintFunc func(processName, processPath string) (model.RuleTarget, string)

type Service interface {
	Start(includedApps []string)
	UpdateIncludedApps(includedApps []string)
	Stop()
	Snapshot() Snapshot
}
