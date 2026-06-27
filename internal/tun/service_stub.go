//go:build !windows

package tun

import (
	"errors"

	"proxy-rule-manager/internal/model"
)

type StubService struct{}

func NewService() Service {
	return &StubService{}
}

func (s *StubService) Start(options model.TunOptions) error {
	return errors.New("TUN 模式当前仅支持 Windows")
}

func (s *StubService) Stop() error {
	return nil
}

func (s *StubService) Status(options model.TunOptions) model.TunRuntimeStatus {
	return model.TunRuntimeStatus{
		Running:   false,
		Available: false,
		Message:   "TUN 模式当前仅支持 Windows",
	}
}
