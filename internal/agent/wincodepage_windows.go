//go:build windows

package agent

import "golang.org/x/sys/windows"

// hostANSICodePage returns the code page wevtutil.exe uses for redirected
// output. wevtutil ignores the console code page when stdout is a pipe and
// writes the process ANSI code page instead.
func hostANSICodePage() int {
	return int(windows.GetACP())
}
