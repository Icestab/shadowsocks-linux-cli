// Package logrotate provides per-start rotation for sscli's own log
// files. An oversized log is renamed aside when the daemon (re)starts.
//
// This is deliberately not an in-process rotating writer: the daemon and
// the sslocal child both write to file descriptors inherited at spawn,
// and reopening under them would require fd-rename machinery the CLI's
// lifecycle doesn't have. Per-start rotation bounds disk usage over
// typical run/stop cycles; long-lived single runs still grow, but each
// restart resets the file.
package logrotate

import "os"

// MaxSize is the size at which a log is rotated (10 MiB).
const MaxSize = 10 << 20

// MaybeRotate renames path to path+".1" when it exceeds MaxSize.
// Best-effort: it never fails the caller.
func MaybeRotate(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Size() < MaxSize {
		return
	}
	_ = os.Rename(path, path+".1")
}