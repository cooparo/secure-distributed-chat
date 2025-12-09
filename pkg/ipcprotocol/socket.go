package ipcprotocol

import (
	"path/filepath"

	"github.com/cooparo/secure-distributed-chat/internal/xdg"
)

func DefaultSocketPath() (string, error) {
	dir, err := xdg.GetRuntimeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "sock"), nil
}
