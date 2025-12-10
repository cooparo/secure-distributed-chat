package ipchandle

import (
	"path/filepath"

	"github.com/cooparo/secure-distributed-chat/internal/xdg"
)

// DefaultSocketPath returns the standard location for the socket
func DefaultSocketPath() (string, error) {
	dir, err := xdg.GetRuntimeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "sock"), nil
}
