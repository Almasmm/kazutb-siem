package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kcsp/platform/internal/dr"
)

func main() {
	if len(os.Args) < 2 {
		fatal(fmt.Errorf("usage: kcsp-dr <backup|restore-drill|restore|list|prune|schedule|self-test> [backup-id]"))
	}
	command := os.Args[1]
	if command == "self-test" {
		if err := dr.SelfTest(); err != nil {
			fatal(err)
		}
		fmt.Println(`{"status":"ok","test":"kcsp-dr-self-test"}`)
		return
	}
	cfg, err := dr.LoadConfig()
	if err != nil {
		fatal(err)
	}
	service, err := dr.NewService(cfg)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch command {
	case "backup":
		result, err := service.Backup(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(result)
	case "restore-drill", "restore":
		backupID := "latest"
		if len(os.Args) > 2 {
			backupID = os.Args[2]
		}
		result, err := service.Restore(ctx, backupID, command == "restore-drill")
		if err != nil {
			fatal(err)
		}
		printJSON(result)
	case "list":
		ids, err := service.List(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"backups": ids})
	case "prune":
		ids, err := service.Prune(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"removed": ids})
	case "schedule":
		for {
			if _, err := service.Backup(ctx); err != nil {
				fatal(err)
			}
			if _, err := service.Prune(ctx); err != nil {
				fatal(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.ScheduleEvery):
			}
		}
	default:
		fatal(fmt.Errorf("unknown KCSP DR command %q", command))
	}
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	log.Printf("KCSP DR failed: %v", err)
	os.Exit(1)
}
