//go:build !windows

package agent

import "context"

// defaultEventReader is unavailable off Windows; the sources refuse to read and
// report ErrUnsupportedSource instead.
func defaultEventReader(ctx context.Context, query eventQuery) (eventReadResult, error) {
	return eventReadResult{}, ErrUnsupportedSource
}
