package risktest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var manifestNames = map[string]bool{
	"changegate-test.yaml":      true,
	"changegate-test.yml":       true,
	"changegate-tests.yaml":     true,
	"changegate-tests.yml":      true,
	".changegate-test.yaml":     true,
	".changegate-test.yml":      true,
	".changegate-tests.yaml":    true,
	".changegate-tests.yml":     true,
	"changegate.risktest.yaml":  true,
	"changegate.risktest.yml":   true,
	"changegate.risktests.yaml": true,
	"changegate.risktests.yml":  true,
}

// Discover returns sorted manifest paths for either one manifest file or a directory tree.
func Discover(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat risk test path %q: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	manifests := make([]string, 0)
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) && current != path {
				return filepath.SkipDir
			}
			return nil
		}
		if isManifestName(entry.Name()) {
			manifests = append(manifests, current)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover risk test manifests under %q: %w", path, err)
	}
	sort.Strings(manifests)
	if len(manifests) == 0 {
		return nil, fmt.Errorf("no ChangeGate risk test manifests found under %q", path)
	}
	return manifests, nil
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".terraform", "node_modules", "vendor":
		return true
	default:
		return strings.HasPrefix(name, ".") && name != "."
	}
}

func isManifestName(name string) bool {
	if manifestNames[name] {
		return true
	}
	return strings.HasSuffix(name, ".changegate-test.yaml") || strings.HasSuffix(name, ".changegate-test.yml")
}
