package daemon

import (
	"errors"
	"os"
	"path/filepath"
)

// StateDir returns the runtime state directory (~/.local/state/sscli),
// overridable via SSCLI_STATE_DIR for tests.
func StateDir() (string, error) {
	if dir := os.Getenv("SSCLI_STATE_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "sscli"), nil
}

// PidFile is the path of the running daemon's pid file.
func PidFile() (string, error) {
	d, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "sscli.pid"), nil
}

// ErrNotRunning is returned when no sscli instance is active.
var ErrNotRunning = errors.New("sscli is not running")
