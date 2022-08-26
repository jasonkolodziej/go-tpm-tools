//go:build !linux && !windows
// +build !linux,!windows

package client

import "errors"

func getRealEventLog() ([]byte, error) {
	return nil, errors.New("failed to get event log: only Linux supported")
}
