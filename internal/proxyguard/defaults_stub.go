//go:build !windows

package proxyguard

import "fmt"

func suggestProgramPaths(upstream string) ([]string, error) {
	return nil, fmt.Errorf("自动识别代理进程路径当前仅支持 Windows，请手动填写受控代理进程路径")
}
