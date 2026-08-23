//go:build !linux

package dr

import (
	"errors"
	"os"
)

func acquireLock(filename string) (*os.File, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if os.IsExist(err) {
		return nil, errors.New("another KCSP backup or restore is active")
	}
	return file, err
}

func releaseLock(file *os.File) {
	if file == nil {
		return
	}
	name := file.Name()
	_ = file.Close()
	_ = os.Remove(name)
}
