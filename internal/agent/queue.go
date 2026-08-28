package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	SourceID       string    `json:"source_id,omitempty"`
	SourceAddress  string    `json:"source_address,omitempty"`
	Payload        []byte    `json:"payload"`
	Cursor         uint64    `json:"cursor,omitempty"`
	Checkpoint     string    `json:"checkpoint,omitempty"`
}

type QueueItem struct {
	QueueID string `json:"queue_id"`
	Event   Event  `json:"event"`
	file    string
}

// DiskQueue is the agent's store-and-forward buffer. Occupancy is tracked in
// memory and adjusted as events are enqueued and acknowledged, because scanning
// the directory on every operation makes each enqueue O(queue depth): at a
// 50k backlog that throttles the whole agent loop and the queue can no longer
// drain faster than it fills.
type DiskQueue struct {
	directory string
	maxBytes  int64
	mu        sync.Mutex
	// measured reports whether count/bytes reflect the directory. It is cleared
	// whenever an operation fails midway so the next call re-scans rather than
	// trusting a total that may have drifted.
	measured bool
	count    int
	bytes    int64
}

func OpenDiskQueue(directory string, maxBytes int64) (*DiskQueue, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" || maxBytes <= 0 {
		return nil, errors.New("queue directory and positive byte limit are required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent queue: %w", err)
	}
	queue := &DiskQueue{directory: directory, maxBytes: maxBytes}
	// One scan at open establishes the baseline for an existing backlog.
	if _, _, err := queue.Depth(); err != nil {
		return nil, err
	}
	return queue, nil
}

// measureLocked rebuilds the cached occupancy from the directory.
func (q *DiskQueue) measureLocked() error {
	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return fmt.Errorf("measure agent queue: %w", err)
	}
	count := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		count++
		bytes += info.Size()
	}
	q.count = count
	q.bytes = bytes
	q.measured = true
	return nil
}

// ensureMeasuredLocked scans only when the cached totals are not trustworthy.
func (q *DiskQueue) ensureMeasuredLocked() error {
	if q.measured {
		return nil
	}
	return q.measureLocked()
}

func (q *DiskQueue) Enqueue(event Event) (QueueItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	item := QueueItem{QueueID: core.NewID("queue"), Event: event}
	return q.enqueueLocked(item, fmt.Sprintf("%020d-%s.event", time.Now().UTC().UnixNano(), item.QueueID))
}

// EnqueueUnique persists an event once for a stable event ID. It is used by
// checkpointed pull sources where a crash can replay the last API page.
func (q *DiskQueue) EnqueueUnique(event Event) (QueueItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if strings.TrimSpace(event.EventID) == "" {
		return QueueItem{}, errors.New("stable event ID is required for unique enqueue")
	}
	digest := sha256.Sum256([]byte(event.EventID))
	key := hex.EncodeToString(digest[:16])
	name := "unique-" + key + ".event"
	destination := filepath.Join(q.directory, name)
	// #nosec G304 -- destination uses the trusted queue directory and a SHA-256-derived fixed filename.
	if body, err := os.ReadFile(destination); err == nil {
		var existing QueueItem
		if err := json.Unmarshal(body, &existing); err != nil || existing.Event.EventID != event.EventID {
			return QueueItem{}, errors.New("invalid unique queued event")
		}
		existing.file = name
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return QueueItem{}, fmt.Errorf("read unique queued event: %w", err)
	}
	item := QueueItem{QueueID: "queue_unique_" + key, Event: event}
	return q.enqueueLocked(item, name)
}

func (q *DiskQueue) enqueueLocked(item QueueItem, name string) (QueueItem, error) {
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
	q.count++
	q.bytes += int64(len(body))
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
	path := filepath.Join(q.directory, item.file)
	// Size is read before the unlink so the cached total stays exact.
	var removed int64
	if info, err := os.Stat(path); err == nil {
		removed = info.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		q.measured = false
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		q.measured = false
		return fmt.Errorf("acknowledge queued event: %w", err)
	}
	if q.count > 0 {
		q.count--
	}
	q.bytes -= removed
	if q.bytes < 0 || q.count == 0 && q.bytes != 0 {
		q.measured = false
	}
	return nil
}

// OldestQueuedAt reports when the oldest still-unacknowledged event was
// enqueued. Queue file names are prefixed with the enqueue time in nanoseconds,
// so the first entry in name order is the oldest. Returns false for an empty
// queue. This walks the directory, so it is called on the heartbeat path only.
func (q *DiskQueue) OldestQueuedAt() (time.Time, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read agent queue: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".event") {
			continue
		}
		separator := strings.IndexByte(name, '-')
		if separator <= 0 {
			continue
		}
		nanoseconds, err := strconv.ParseInt(name[:separator], 10, 64)
		if err != nil || nanoseconds <= 0 {
			continue
		}
		return time.Unix(0, nanoseconds).UTC(), true, nil
	}
	return time.Time{}, false, nil
}

func (q *DiskQueue) Depth() (int, int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.ensureMeasuredLocked(); err != nil {
		return 0, 0, err
	}
	return q.count, q.bytes, nil
}

func (q *DiskQueue) sizeLocked() (int64, error) {
	if err := q.ensureMeasuredLocked(); err != nil {
		return 0, err
	}
	return q.bytes, nil
}
