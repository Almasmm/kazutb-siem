//go:build !windows

package agent

import (
	"errors"
	"os"
)

func securePrivateFile(file *os.File) error {
	return file.Chmod(0o600)
}

// ValidatePrivateFileSecurity enforces the platform-native private-state
// invariant. Unix requires no group or world permission bits.
func ValidatePrivateFileSecurity(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("agent private state file has group or world permissions")
	}
	return nil
}
