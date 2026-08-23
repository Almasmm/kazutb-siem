//go:build windows

package main

import (
	"context"
	"errors"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "KCSPAgent"

type windowsAgentService struct {
	logger *slog.Logger
}

func runProcess(logger *slog.Logger) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return runConsole(logger)
	}
	return svc.Run(windowsServiceName, &windowsAgentService{logger: logger})
}

func (s *windowsAgentService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		completed <- run(ctx, s.logger)
	}()

	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- status
	stopping := false
	for {
		select {
		case err := <-completed:
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("KCSP Windows service runtime failed", "error", err)
				return true, 1
			}
			return false, 0
		case request, open := <-requests:
			if !open {
				cancel()
				continue
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				if !stopping {
					stopping = true
					status = svc.Status{State: svc.StopPending}
					changes <- status
					cancel()
				}
			default:
				s.logger.Warn("unsupported Windows service control request", "command", request.Cmd)
			}
		}
	}
}
