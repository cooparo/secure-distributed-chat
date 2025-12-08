package ipchandle

import (
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the standard location for the socket
func DefaultSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = "/tmp"
	}
	return filepath.Join(dir, "grat.sock")
}
