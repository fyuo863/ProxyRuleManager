//go:build !windows

package appmonitor

import "proxy-rule-manager/internal/model"

type StubService struct{}

func NewService(addLog func(model.TrafficLog), updateLog func(string, func(*model.TrafficLog)), routeHint RouteHintFunc) Service {
	return &StubService{}
}

func (s *StubService) Start(includedApps []string) {}

func (s *StubService) UpdateIncludedApps(includedApps []string) {}

func (s *StubService) Stop() {}

func (s *StubService) Snapshot() Snapshot {
	return Snapshot{}
}
