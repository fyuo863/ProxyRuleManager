package netroute

import "proxy-rule-manager/internal/model"

func ListDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	return listDefaultIPv4Routes()
}
