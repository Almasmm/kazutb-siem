package dr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type commandRunner interface {
	Run(context.Context, time.Duration, io.Writer, []string, string, ...string) error
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, timeout time.Duration, stdout io.Writer, environment []string, name string, arguments ...string) error {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, name, arguments...)
	command.Env = append(os.Environ(), environment...)
	command.Stdout = stdout
	var stderr bytes.Buffer
	command.Stderr = &limitedWriter{writer: &stderr, remaining: 16 * 1024}
	if err := command.Run(); err != nil {
		if commandContext.Err() != nil {
			return fmt.Errorf("%s timed out: %w", name, commandContext.Err())
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return fmt.Errorf("%s failed: %w", name, err)
		}
		return fmt.Errorf("%s failed: %s", name, message)
	}
	return nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	if w.remaining <= 0 {
		return original, nil
	}
	if len(value) > w.remaining {
		value = value[:w.remaining]
	}
	_, err := w.writer.Write(value)
	w.remaining -= len(value)
	return original, err
}
