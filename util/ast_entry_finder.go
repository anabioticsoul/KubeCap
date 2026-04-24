// util/entrypoints.go
package util

import (
	"encoding/csv"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EntrypointRecord stores one CSV row for analysis.
// ManifestPath is optional and comes from column 1 when present.
type EntrypointRecord struct {
	ManifestPath string
	Entrypoint   string
}

// LoadEntrypointFile reads entrypoints from CSV-like files.
// Compatibility rules:
// - If a row has 3+ columns and column 2 is "null", column 3 is treated as the entrypoint.
// - If a row has 2+ columns, column 2 is treated as the entrypoint.
// - If a row has only 1 column, that value is treated as the entrypoint.
// - Empty rows and header-like "entrypoint" values are ignored.
func LoadEntrypointFile(path string) ([]string, error) {
	records, err := LoadEntrypointRecords(path)
	if err != nil {
		return nil, err
	}

	entries := make([]string, 0, len(records))
	for _, rec := range records {
		entries = append(entries, rec.Entrypoint)
	}
	return entries, nil
}

// LoadEntrypointRecords reads entrypoint rows and preserves the manifest hint
// from column 1 when a 2-column CSV format is used.
func LoadEntrypointRecords(path string) ([]EntrypointRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []EntrypointRecord
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		if len(row) == 0 {
			continue
		}

		manifest := ""
		entry := ""
		col2 := ""
		if len(row) > 1 {
			manifest = strings.TrimSpace(row[0])
			col2 = strings.TrimSpace(row[1])
			entry = col2
		}
		if len(row) > 2 && strings.EqualFold(col2, "null") {
			entry = strings.TrimSpace(row[2])
		}
		if entry == "" {
			entry = strings.TrimSpace(row[0])
		}
		if entry == "" || strings.EqualFold(entry, "entrypoint") {
			continue
		}

		records = append(records, EntrypointRecord{
			ManifestPath: manifest,
			Entrypoint:   entry,
		})
	}

	return records, nil
}

// ScanAllSubdirs scans each direct subdirectory of parentDir and dumps a CSV for each subdir.
func ScanAllSubdirs(parentDir, projectRoot string) error {
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		scanDir := filepath.Join(parentDir, e.Name())

		// each subdir -> one CSV
		if err := ScanAndDumpEntrypoints(scanDir, projectRoot); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] scan failed for %s: %v\n", scanDir, err)
		} else {
			fmt.Printf("[INFO] scan succeeded for %s\n", scanDir)
		}
	}
	return nil
}

// FindMainFilesByAST finds Go entrypoints by syntax scanning only:
// package main + func main() with no receiver, no params, no results.
// This avoids missing entrypoints due to build/typecheck failures.
func FindMainFilesByAST(scanDir string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()

	shouldSkipDir := func(path string) bool {
		base := filepath.Base(path)
		if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
			return true
		}
		return false
	}

	err := filepath.WalkDir(scanDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// ignore I/O errors and continue
			return nil
		}

		if d.IsDir() {
			if path != scanDir && shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			// ignore parse errors and continue
			return nil
		}
		if file.Name == nil || file.Name.Name != "main" {
			return nil
		}

		if hasMainFunc(file) {
			out = append(out, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func hasMainFunc(f *ast.File) bool {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Name == nil || fd.Name.Name != "main" {
			continue
		}
		// must be function, not method
		if fd.Recv != nil {
			continue
		}
		// must be main() with no params and no results
		if fd.Type == nil {
			continue
		}
		if fd.Type.Params != nil && len(fd.Type.Params.List) != 0 {
			continue
		}
		if fd.Type.Results != nil && len(fd.Type.Results.List) != 0 {
			continue
		}
		return true
	}
	return false
}

// RelPathOfFile returns file path relative to project root, normalized to ./ and forward slashes.
func RelPathOfFile(projectRoot, filename string) (string, error) {
	if filename == "" {
		return "", fmt.Errorf("empty filename")
	}

	absFile, err := filepath.Abs(filename)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(projectRoot, absFile)
	if err != nil {
		return "", err
	}

	rel = filepath.ToSlash(rel)
	if !strings.HasPrefix(rel, "./") {
		rel = "./" + rel
	}
	return rel, nil
}

// ScanAndDumpEntrypoints scans scanDir and writes a CSV (one path per line) into:
// input/entrypoints/CNCFs/incubating/<basename(scanDir)>.csv
func ScanAndDumpEntrypoints(scanDir, projectRoot string) error {
	// 1) find main files by AST scan
	files, err := FindMainFilesByAST(scanDir)
	if err != nil {
		return err
	}

	// 2) csv name = scanDir base
	scanDir = filepath.Clean(scanDir)
	csvName := filepath.Base(scanDir) + ".csv"

	// 3) output dir
	//outDir := filepath.Join("input", "entrypoints", "CNCFs", "incubating")
	outDir := filepath.Join("input", "entrypoints", "OSS", "Github")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(outDir, csvName)

	// 4) write file list
	lines := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := RelPathOfFile(projectRoot, f)
		if err != nil {
			continue
		}
		lines = append(lines, rel)
	}
	sort.Strings(lines)

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	} else {
		// keep consistent: create empty file
		content = ""
	}

	return os.WriteFile(outPath, []byte(content), 0o644)
}
