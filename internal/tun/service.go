package tun

import "proxy-rule-manager/internal/model"

type Service interface {
	Start(options model.TunOptions) error
	Stop() error
	Status(options model.TunOptions) model.TunRuntimeStatus
}
