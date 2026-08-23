package collector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/agent"
	"github.com/kcsp/platform/internal/ingest"
)

type FileSource struct {
	Path       string `json:"path"`
	SourceID   string `json:"source_id"`
	Format     string `json:"format,omitempty"`
	StartAtEnd bool   `json:"start_at_end,omitempty"`
}

type FileTailConfig struct {
	Sources             []FileSource
	CheckpointDirectory string
	PollInterval        time.Duration
	MaximumEventBytes   int
	MaximumLinesPerPoll int
	Queue               *agent.DiskQueue
}

type FileTailer struct {
	config      FileTailConfig
	checkpoints map[string]fileCheckpoint
	ready       chan struct{}
	once        sync.Once
}

type fileCheckpoint struct {
	Path        string    `json:"path"`
	Offset      int64     `json:"offset"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func ParseFileSourcesJSON(value string) ([]FileSource, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "[]" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var sources []FileSource
	if err := decoder.Decode(&sources); err != nil {
		return nil, fmt.Errorf("decode KCSP_COLLECTOR_FILE_SOURCES_JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("KCSP_COLLECTOR_FILE_SOURCES_JSON contains trailing data")
	}
	if len(sources) > 256 {
		return nil, errors.New("at most 256 file sources are allowed per collector")
	}
	return sources, nil
}

func NewFileTailer(config FileTailConfig) (*FileTailer, error) {
	if len(config.Sources) == 0 || config.Queue == nil {
		return nil, errors.New("file sources and persistent queue are required")
	}
	config.CheckpointDirectory = strings.TrimSpace(config.CheckpointDirectory)
	if config.CheckpointDirectory == "" {
		return nil, errors.New("file checkpoint directory is required")
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.MaximumEventBytes <= 0 || config.MaximumEventBytes > ingest.MaxEventBytes {
		config.MaximumEventBytes = ingest.MaxEventBytes
	}
	if config.MaximumLinesPerPoll <= 0 || config.MaximumLinesPerPoll > 10000 {
		config.MaximumLinesPerPoll = 1000
	}
	if err := os.MkdirAll(config.CheckpointDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create file checkpoint directory: %w", err)
	}
	seen := map[string]bool{}
	checkpoints := map[string]fileCheckpoint{}
	for index := range config.Sources {
		source := &config.Sources[index]
		source.Path = filepath.Clean(strings.TrimSpace(source.Path))
		source.SourceID = strings.TrimSpace(source.SourceID)
		source.Format = strings.TrimSpace(source.Format)
		if !filepath.IsAbs(source.Path) || source.Path == string(filepath.Separator) || len(source.Path) > 256 || source.SourceID == "" || len(source.SourceID) > 128 || strings.ContainsAny(source.SourceID, "\r\n") {
			return nil, fmt.Errorf("invalid file source %d: absolute path and canonical source_id are required", index)
		}
		if source.Format != "" && !validCollectorFormat(source.Format) {
			return nil, fmt.Errorf("invalid file source format %q", source.Format)
		}
		if seen[source.Path] {
			return nil, fmt.Errorf("duplicate file source path %q", source.Path)
		}
		seen[source.Path] = true
		checkpoint, found, err := loadFileCheckpoint(config.CheckpointDirectory, source.Path)
		if err != nil {
			return nil, err
		}
		if found {
			checkpoints[source.Path] = checkpoint
		}
	}
	return &FileTailer{config: config, checkpoints: checkpoints, ready: make(chan struct{})}, nil
}

func (t *FileTailer) Ready() <-chan struct{} { return t.ready }

func (t *FileTailer) Run(ctx context.Context) error {
	t.once.Do(func() { close(t.ready) })
	ticker := time.NewTicker(t.config.PollInterval)
	defer ticker.Stop()
	for {
		for _, source := range t.config.Sources {
			if _, err := t.pollSource(ctx, source); err != nil && !errors.Is(err, agent.ErrQueueFull) && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (t *FileTailer) pollSource(ctx context.Context, source FileSource) (int, error) {
	info, err := os.Lstat(source.Path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, fmt.Errorf("file source %q must be a regular non-symlink file", source.Path)
	}
	file, err := os.Open(source.Path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	fingerprint, err := filePrefixFingerprint(file, info.Size())
	if err != nil {
		return 0, err
	}
	checkpoint, found := t.checkpoints[source.Path]
	if !found {
		checkpoint = fileCheckpoint{Path: source.Path}
		if source.StartAtEnd {
			checkpoint.Offset = info.Size()
			checkpoint.Fingerprint = fingerprint
			if err := t.commitCheckpoint(checkpoint); err != nil {
				return 0, err
			}
			return 0, nil
		}
	}
	if checkpoint.Offset > info.Size() || checkpoint.Fingerprint != "" && fingerprint != "" && checkpoint.Fingerprint != fingerprint {
		checkpoint.Offset = 0
	}
	if checkpoint.Fingerprint == "" && fingerprint != "" {
		checkpoint.Fingerprint = fingerprint
	}
	if _, err := file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek file source %q: %w", source.Path, err)
	}
	reader := bufio.NewReaderSize(file, t.config.MaximumEventBytes+2)
	processed := 0
	linesRead := 0
	dirty := false
	for linesRead < t.config.MaximumLinesPerPoll {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > t.config.MaximumEventBytes+2 {
			return processed, fmt.Errorf("file source %q contains an event larger than %d bytes", source.Path, t.config.MaximumEventBytes)
		}
		if errors.Is(readErr, io.EOF) {
			if dirty {
				if err := t.commitCheckpoint(checkpoint); err != nil {
					return processed, err
				}
			}
			return processed, nil
		}
		if readErr != nil {
			return processed, fmt.Errorf("read file source %q: %w", source.Path, readErr)
		}
		linesRead++
		nextOffset := checkpoint.Offset + int64(len(line))
		payload := strings.TrimRight(string(line), "\r\n")
		if strings.TrimSpace(payload) != "" {
			event, eventErr := networkEvent(source.SourceID, source.Path, []byte(payload), time.Now().UTC())
			if eventErr != nil {
				return processed, eventErr
			}
			if source.Format != "" {
				event.Format = source.Format
			}
			if _, queueErr := t.config.Queue.Enqueue(event); queueErr != nil {
				if dirty {
					if checkpointErr := t.commitCheckpoint(checkpoint); checkpointErr != nil {
						return processed, errors.Join(queueErr, checkpointErr)
					}
				}
				return processed, queueErr
			}
			processed++
		}
		checkpoint.Offset = nextOffset
		checkpoint.Fingerprint = fingerprint
		dirty = true
	}
	if dirty {
		if err := t.commitCheckpoint(checkpoint); err != nil {
			return processed, err
		}
	}
	return processed, nil
}

func (t *FileTailer) commitCheckpoint(checkpoint fileCheckpoint) error {
	checkpoint.UpdatedAt = time.Now().UTC()
	body, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(t.config.CheckpointDirectory, ".checkpoint-*")
	if err != nil {
		return fmt.Errorf("create file checkpoint: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	destination := fileCheckpointPath(t.config.CheckpointDirectory, checkpoint.Path)
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("commit file checkpoint: %w", err)
	}
	t.checkpoints[checkpoint.Path] = checkpoint
	return nil
}

func loadFileCheckpoint(directory, sourcePath string) (fileCheckpoint, bool, error) {
	body, err := os.ReadFile(fileCheckpointPath(directory, sourcePath))
	if errors.Is(err, os.ErrNotExist) {
		return fileCheckpoint{}, false, nil
	}
	if err != nil {
		return fileCheckpoint{}, false, fmt.Errorf("read file checkpoint: %w", err)
	}
	var checkpoint fileCheckpoint
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil || checkpoint.Path != sourcePath || checkpoint.Offset < 0 {
		return fileCheckpoint{}, false, fmt.Errorf("invalid checkpoint for file source %q", sourcePath)
	}
	return checkpoint, true, nil
}

func fileCheckpointPath(directory, sourcePath string) string {
	digest := sha256.Sum256([]byte(sourcePath))
	return filepath.Join(directory, hex.EncodeToString(digest[:16])+".json")
}

func filePrefixFingerprint(file *os.File, size int64) (string, error) {
	const fingerprintBytes = 64
	if size < fingerprintBytes {
		return "", nil
	}
	prefix := make([]byte, fingerprintBytes)
	if _, err := file.ReadAt(prefix, 0); err != nil {
		return "", fmt.Errorf("fingerprint file source: %w", err)
	}
	digest := sha256.Sum256(prefix)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
