//go:build !windows

package agent

// hostANSICodePage reports UTF-8 on non-Windows hosts, where the Windows Event
// Log sources are unsupported and only the decoder unit tests run.
func hostANSICodePage() int {
	return 65001
}
