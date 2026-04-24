package deviation

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDefaultCaps reads default capabilities from file (one capability per line).
func LoadDefaultCaps(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open default caps file error: %w", err)
	}
	defer f.Close()

	defaultCaps := make(map[string]struct{})
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		cap := strings.TrimSpace(scanner.Text())
		if cap == "" || strings.HasPrefix(cap, "#") {
			continue
		}
		defaultCaps[strings.ToUpper(cap)] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return defaultCaps, nil
}

// DeviationAnalysis deviation analysis: requiredCaps vs defaultCaps
func DeviationAnalysis(requiredCaps []string, defaultCaps map[string]struct{}) (needAdd, canDrop, intersection []string) {

	requiredSet := make(map[string]struct{})
	for _, c := range requiredCaps {
		requiredSet[strings.ToUpper(c)] = struct{}{}
	}

	// 1. needAdd = required - default
	for req := range requiredSet {
		if _, ok := defaultCaps[req]; !ok {
			needAdd = append(needAdd, req)
		}
	}

	// 2. canDrop = default - required
	for def := range defaultCaps {
		if _, ok := requiredSet[def]; !ok {
			canDrop = append(canDrop, def)
		}
	}

	// 3. intersection
	for req := range requiredSet {
		if _, ok := defaultCaps[req]; ok {
			intersection = append(intersection, req)
		}
	}

	return
}
