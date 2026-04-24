package util

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

//func LoadEntrypointFile(path string) ([]string, error) {
//	f, err := os.Open(path)
//	if err != nil {
//		return nil, err
//	}
//	defer f.Close()
//
//	var entries []string
//	scanner := bufio.NewScanner(f)
//
//	for scanner.Scan() {
//		line := strings.TrimSpace(scanner.Text())
//		if line == "" {
//			continue
//		}
//		entries = append(entries, line)
//	}
//
//	if err := scanner.Err(); err != nil {
//		return nil, err
//	}
//	return entries, nil
//}
//
//func ScanAllSubdirs(parentDir, projectRoot string) error {
//	entries, err := os.ReadDir(parentDir)
//	if err != nil {
//		return err
//	}
//
//	for _, e := range entries {
//		if !e.IsDir() {
//			continue
//		}
//
//		scanDir := filepath.Join(parentDir, e.Name())
//
//		// 每个子目录单独生成一个 CSV
//		if err := ScanAndDumpEntrypoints(scanDir, projectRoot); err != nil {
//			fmt.Fprintf(os.Stderr,
//				"[WARN] scan failed for %s: %v\n",
//				scanDir, err,
//			)
//		}
//	}
//	return nil
//}

// FindEntrypoints 在给定目录中查找所有 Go entrypoints（package main 的 main()）
func FindEntrypoints(dir string) ([]*ssa.Function, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo,
		Dir: dir,
		Env: append(os.Environ(),
			"GOOS=linux",
			"GOARCH=amd64"),
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("package load errors")
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
	prog.Build()

	var entrypoints []*ssa.Function

	for _, ssaPkg := range ssaPkgs {
		if ssaPkg == nil {
			continue
		}
		if ssaPkg.Pkg.Name() != "main" {
			continue
		}
		if mem, ok := ssaPkg.Members["main"]; ok {
			if fn, ok := mem.(*ssa.Function); ok {
				entrypoints = append(entrypoints, fn)
			}
		}
	}
	return entrypoints, nil
}

// RelPathOfFunction 计算 fn 所在文件相对于 project root 的路径
func RelPathOfFunction(root string, fn *ssa.Function) (string, error) {
	pos := fn.Prog.Fset.Position(fn.Pos())
	if pos.Filename == "" {
		return "", fmt.Errorf("empty filename")
	}

	absFile, err := filepath.Abs(pos.Filename)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, absFile)
	if err != nil {
		return "", err
	}
	return rel, nil
}

//// ScanAndDumpEntrypoints 扫描目录并输出 CSV
//func ScanAndDumpEntrypoints(scanDir, projectRoot string) error {
//	// 1. 找 entrypoints
//	fns, err := FindEntrypoints(scanDir)
//	if err != nil {
//		return err
//	}
//
//	// 2. CSV 文件名 = 扫描目录名
//	scanDir = filepath.Clean(scanDir)
//	csvName := filepath.Base(scanDir) + ".csv"
//
//	// 3. 输出路径
//	outDir := filepath.Join(
//		"input", "entrypoints", "CNCFs", "incubating",
//	)
//	if err := os.MkdirAll(outDir, 0o755); err != nil {
//		return err
//	}
//
//	outPath := filepath.Join(outDir, csvName)
//
//	// 4. 写 CSV
//	var lines []string
//	for _, fn := range fns {
//		rel, err := RelPathOfFunction(projectRoot, fn)
//		if err != nil {
//			continue
//		}
//
//		// 统一使用 `/`，并在前面加 `./`
//		rel = filepath.ToSlash(rel)
//		if !strings.HasPrefix(rel, "./") {
//			rel = "./" + rel
//		}
//		lines = append(lines, rel)
//	}
//
//	content := strings.Join(lines, "\n") + "\n"
//	return os.WriteFile(outPath, []byte(content), 0o644)
//}
