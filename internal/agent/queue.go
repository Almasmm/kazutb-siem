package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kcsp/platform/internal/core"
)

var ErrQueueFull = errors.New("agent persistent queue is full")

type Event struct {
	Format         string    `json:"format"`
	ContentType    string    `json:"content_type"`
	EventID        string    `json:"event_id"`
	EventTimestamp time.Time `json:"event_timestamp"`
	Payload        []byte    `json:"payload"`
	Cursor         uint64    `json:"cursor,omitempty"`
}

type QueueItem struct {
	QueueID string `json:"queue_id"`
	Event   Event  `json:"event"`
	file    string
}

type DiskQueue struct {
	directory string
	maxBytes  int64
	mu        sync.Mutex
}

func OpenDiskQueue(directory string, maxBytes int64) (*DiskQueue, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" || maxBytes <= 0 {
		return nil, errors.New("queue directory and positive byte limit are required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent queue: %w", err)
	}
	return &DiskQueue{directory: directory, maxBytes: maxBytes}, nil
}

func (q *DiskQueue) Enqueue(event Event) (QueueItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	item := QueueItem{QueueID: core.NewID("queue"), Event: event}
	body, err := json.Marshal(item)
	if err != nil {
		return QueueItem{}, fmt.Errorf("encode queued event: %w", err)
	}
	used, err := q.sizeLocked()
	if err != nil {
		return QueueItem{}, err
	}
	if used+int64(len(body)) > q.maxBytes {
		return QueueItem{}, fmt.Errorf("%w: used=%d incoming=%d limit=%d", ErrQueueFull, used, len(body), q.maxBytes)
	}
	name := fmt.Sprintf("%020d-%s.event", time.Now().UTC().UnixNano(), item.QueueID)
	temporary, err := os.CreateTemp(q.directory, ".pending-*")
	if err != nil {
		return QueueItem{}, fmt.Errorf("create queued event: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return QueueItem{}, fmt.Errorf("secure queued event: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return QueueItem{}, fmt.Errorf("write queued event: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return QueueItem{}, fmt.Errorf("sync queued event: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return QueueItem{}, fmt.Errorf("close queued event: %w", err)
	}
	item.file = name
	if err := os.Rename(temporaryName, filepath.Join(q.directory, name)); err != nil {
		return QueueItem{}, fmt.Errorf("commit queued event: %w", err)
	}
	return item, nil
}

func (q *DiskQueue) Peek(limit int) ([]QueueItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return nil, fmt.Errorf("read agent queue: %w", err)
	}
	items := make([]QueueItem, 0, min(limit, len(entries)))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(q.directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read queued event %s: %w", entry.Name(), err)
		}
		var item QueueItem
		if err := json.Unmarshal(body, &item); err != nil {
			return nil, fmt.Errorf("decode queued event %s: %w", entry.Name(), err)
		}
		item.file = entry.Name()
		items = append(items, item)
		if len(items) == limit {
			break
		}
	}
	return items, nil
}

func (q *DiskQueue) Ack(item QueueItem) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if item.file == "" || filepath.Base(item.file) != item.file || !strings.HasSuffix(item.file, ".event") {
		return errors.New("invalid queued event reference")
	}
	if err := os.Remove(filepath.Join(q.directory, item.file)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("acknowledge queued event: %w", err)
	}
	return nil
}

func (q *DiskQueue) Depth() (int, int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return 0, 0, err
	}
	count := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		count++
		bytes += info.Size()
	}
	return count, bytes, nil
}

func (q *DiskQueue) sizeLocked() (int64, error) {
	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return 0, fmt.Errorf("measure agent queue: %w", err)
	}
	var size int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		size += info.Size()
	}
	return size, nil
}
