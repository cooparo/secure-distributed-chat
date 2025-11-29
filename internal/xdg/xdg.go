package xdg

import (
	"errors"
	"os"
	"path/filepath"
)

func GetDataHome() (string, error) {
	dir := os.Getenv("XDG_DATA_HOME")
	if len(dir) == 0 {
		homedir := os.Getenv("HOME")
		if len(homedir) == 0 {
			return "", errors.New("$HOME not set")
		}

		dir = filepath.Join(homedir, ".local", "share")
	}

	dir = filepath.Join(dir, "grat")

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	return dir, nil
}

func GetRuntimeDir() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if len(dir) == 0 {
		uid := os.Getenv("UID")
		if len(uid) == 0 {
			return "", errors.New("$UID not set")
		}

		dir = filepath.Join("/", "tmp", "grat."+uid)
	} else {
		dir = filepath.Join(dir, "grat")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	return dir, nil
}
