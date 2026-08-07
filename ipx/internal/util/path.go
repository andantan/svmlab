package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// FindProjectRoot walks upward from the working directory until it finds the
// directory holding config.yaml, so a binary can be started from anywhere in
// the tree.
func FindProjectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := wd
	for {
		if fileExists(filepath.Join(dir, "config.yaml")) {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root not found from %s", wd)
		}

		dir = parent
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
