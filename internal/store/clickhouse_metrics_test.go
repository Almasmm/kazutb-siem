package store

import "testing"

func TestUint64ToIntBoundaries(t *testing.T) {
	maxInt := uint64(^uint(0) >> 1)
	got, err := uint64ToInt(maxInt)
	if err != nil {
		t.Fatalf("convert maximum int: %v", err)
	}
	if uint64(got) != maxInt {
		t.Fatalf("convert maximum int: got %d, want %d", got, maxInt)
	}

	if _, err := uint64ToInt(maxInt + 1); err == nil {
		t.Fatal("expected overflow conversion to fail")
	}
}
