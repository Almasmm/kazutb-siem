package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type noOpLogCloser struct{}

func (noOpLogCloser) Close() error { return nil }

type rotatingLogWriter struct {
	mu          sync.Mutex
	path        string
	maximumSize int64
	backups     int
	file        *os.File
	size        int64
}

func newAgentLogger() (*slog.Logger, io.Closer, error) {
	path := strings.TrimSpace(os.Getenv("KCSP_AGENT_LOG_FILE"))
	if path == "" {
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})), noOpLogCloser{}, nil
	}
	maximumSize := envInt64("KCSP_AGENT_LOG_MAX_BYTES", 10<<20)
	backups := int(envInt64("KCSP_AGENT_LOG_BACKUPS", 5))
	if backups > 20 {
		backups = 20
	}
	writer, err := openRotatingLogWriter(path, maximumSize, backups)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})), writer, nil
}

func openRotatingLogWriter(path string, maximumSize int64, backups int) (*rotatingLogWriter, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("agent log path is required")
	}
	if maximumSize < 1024 {
		return nil, errors.New("agent log maximum size must be at least 1024 bytes")
	}
	if backups < 1 {
		return nil, errors.New("agent log backup count must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &rotatingLogWriter{path: path, maximumSize: maximumSize, backups: backups, file: file, size: info.Size()}, nil
}

func (w *rotatingLogWriter) Write(body []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(body)) > w.maximumSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	written, err := w.file.Write(body)
	w.size += int64(written)
	return written, err
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingLogWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	for index := w.backups; index >= 1; index-- {
		target := w.path + "." + strconv.Itoa(index)
		_ = os.Remove(target)
		if index == 1 {
			if err := os.Rename(w.path, target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		source := w.path + "." + strconv.Itoa(index-1)
		if err := os.Rename(source, target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = file
	w.size = 0
	return nil
}
