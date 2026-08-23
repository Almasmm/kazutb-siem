package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingLogWriterBoundsActiveFileAndKeepsBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	writer, err := openRotatingLogWriter(path, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Repeat([]byte("x"), 700)
	if _, err := writer.Write(line); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(line); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if active.Size() != int64(len(line)) || backup.Size() != int64(len(line)) {
		t.Fatalf("unexpected log sizes: active=%d backup=%d", active.Size(), backup.Size())
	}
}
