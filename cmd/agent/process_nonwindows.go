//go:build !windows

package main

import "log/slog"

func runProcess(logger *slog.Logger) error {
	return runConsole(logger)
}
