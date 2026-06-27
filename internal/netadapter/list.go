package netadapter

import "proxy-rule-manager/internal/model"

func List() ([]model.NetworkAdapterOption, error) {
	return list()
}
