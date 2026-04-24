package util

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ar-go-tools/fake/analysis/deviation"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type SyscallCategories struct {
	SyscallTraps    []string // 通用系统调用入口（trap）
	SyscallWrappers []string // wrapper封装
	SyscallRuntimes []string // runtime 内部系统调用
}

func ExtractReachableFunctionsFromCG(cg *callgraph.Graph) []*ssa.Function {
	if cg == nil {
		return nil
	}

	reachableFunctions := make([]*ssa.Function, 0, len(cg.Nodes))
	for fn := range cg.Nodes {
		if fn == nil {
			continue
		}
		//if strings.Contains(fn.Name(), "setrlimit") {
		//	break
		//}
		reachableFunctions = append(reachableFunctions, fn)
	}
	return reachableFunctions
}

func IdentifySyscallsFromReachableFunctions(pattern string, funs []*ssa.Function) (*SyscallCategories, error) {
	// ... packages.Load + SSA 构建 + pointer 分析同之前 ...

	cats := &SyscallCategories{
		SyscallTraps:    []string{},
		SyscallWrappers: []string{},
		SyscallRuntimes: []string{},
	}

	runtimeSyscallKeywords := []string{
		"futex", "clone", "epoll",
		"rt_sig", "mmap", "munmap",
		"write1", "exit", "usleep",
		"madvise",
	}

	seenTrap := make(map[string]struct{})
	seenWrapper := make(map[string]struct{})
	seenRuntime := make(map[string]struct{})

	//for fn := range ssautil.AllFunctions(prog) {

	for _, fn := range funs {

		// may null / may synthetic function / no blocks
		if fn == nil || fn.Pkg == nil || fn.Blocks == nil {
			continue
		}

		fullName := fn.String()
		pkgPath := fn.Pkg.Pkg.Path()
		fnName := fn.Name()
		lowerFull := strings.ToLower(fullName)

		// 1. SyscallTraps
		if pkgPath == "syscall" &&
			(fnName == "Syscall" || fnName == "Syscall6" ||
				fnName == "RawSyscall" || fnName == "RawSyscall6") {

			if _, ok := seenTrap[fullName]; !ok {
				cats.SyscallTraps = append(cats.SyscallTraps, fullName)
				seenTrap[fullName] = struct{}{}
			}
			continue
		}

		// 2. SyscallRuntimes
		if pkgPath == "runtime" {
			for _, key := range runtimeSyscallKeywords {
				if strings.Contains(lowerFull, "runtime."+key) {
					if _, ok := seenRuntime[fullName]; !ok {
						cats.SyscallRuntimes = append(cats.SyscallRuntimes, fullName)
						seenRuntime[fullName] = struct{}{}
					}
					break
				}
			}
		}

		// 3. SyscallWrappers
		if pkgPath == "syscall" || pkgPath == "unix" || pkgPath == "golang.org/x/sys/unix" || strings.HasPrefix(pkgPath, "golang.org/x/sys") {
			// 跳过 Trap
			if _, ok := seenTrap[fullName]; ok {
				continue
			}
			if _, ok := seenWrapper[fullName]; !ok {
				cats.SyscallWrappers = append(cats.SyscallWrappers, fullName)
				seenWrapper[fullName] = struct{}{}
			}
		}
	}
	if cats.SyscallWrappers == nil && cats.SyscallRuntimes == nil && cats.SyscallTraps == nil {
		return nil, fmt.Errorf("no syscall wrappers/traps/runtimes found with pattern %s", pattern)
	}
	return cats, nil
}

func GetSyscallFromLibs(srcPath string) []string {
	// --- 0. 读取 CSV 中的函数名（大小写不敏感） ---
	csvPath := srcPath // 改成你自己的路径
	csvFuncs := make(map[string]struct{})

	{
		f, err := os.Open(csvPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open csv error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			name := strings.TrimSpace(scanner.Text())
			if name == "" {
				continue
			}
			csvFuncs[strings.ToLower(name)] = struct{}{} // 小写化存储
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "csv scan error: %v\n", err)
			os.Exit(1)
		}
	}

	// 1. 定位 golang.org/x/sys/unix 目录
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles,
	}, "golang.org/x/sys/unix")
	if err != nil || len(pkgs) == 0 {
		fmt.Fprintf(os.Stderr, "load unix package error: %v\n", err)
		os.Exit(1)
	}
	unixDir := filepath.Dir(pkgs[0].GoFiles[0])
	fmt.Println("unix dir:", unixDir)

	// 2. 提取 syscall wrapper 函数
	fset := token.NewFileSet()
	extracted := map[string]struct{}{}

	err = filepath.Walk(unixDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		base := filepath.Base(path)
		if !(strings.HasPrefix(base, "syscall_") || strings.HasPrefix(base, "zsyscall_")) {
			return nil
		}
		if !strings.HasSuffix(base, ".go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s error: %v\n", path, err)
			return nil
		}

		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil {
				continue
			}
			name := fd.Name.Name
			nameLower := strings.ToLower(name)

			// --- 3. 判断是否在 CSV（忽略大小写） ---
			if _, ok := csvFuncs[nameLower]; ok {
				extracted[name] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(extracted))
	for name := range extracted {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

type Syscall struct {
	NR    int    // syscall number
	ABI   string // common / 64 / x32
	Name  string // read / write / ...
	Entry string // __x64_sys_read / ...
}

func DumpToFile(funcs []string, dstPath string) {
	out := dstPath
	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s error: %v\n", filepath.Dir(out), err)
		return
	}

	// 排序并写入本地缓存文件
	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create out file error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	for _, name := range funcs {
		fmt.Fprintln(f, name)
	}

	fmt.Printf("dumped %d syscalls to %s\n", len(funcs), out)
}

func GetSyscallByDOC(syscallTableURL string) []string {

	// 1. 本地没有缓存，在线拉取
	resp, err := http.Get(syscallTableURL)
	if err != nil {
		panic(fmt.Errorf("download syscall table: %w", err))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Errorf("read body: %w", err))
	}

	// Gitiles ?format=TEXT 返回的是 base64 编码的一整行文本
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		panic(fmt.Errorf("decode base64: %w", err))
	}

	syscalls, err := parseSyscallTable(string(decoded))
	if err != nil {
		panic(err)
	}

	// 2. 收集 syscall 名称
	funcs := make([]string, 0, len(syscalls))
	for _, sc := range syscalls {
		// sc.Name 是 syscall 名，如 "openat", "mount"
		if sc.Name == "" {
			continue
		}
		funcs = append(funcs, sc.Name)
	}
	sort.Strings(funcs)
	return funcs
}

func parseSyscallTable(table string) ([]Syscall, error) {
	var out []Syscall

	scanner := bufio.NewScanner(strings.NewReader(table))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 空行 / 注释
		}

		fields := strings.Fields(line)
		// 标准行格式：<nr> <abi> <name> <entry> [可能还有其它列]
		if len(fields) < 4 {
			continue // 非标准行（比如某些 “Not implemented” 行），直接略过
		}

		nr, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("parse nr from %q: %w", line, err)
		}

		sc := Syscall{
			NR:    nr,
			ABI:   fields[1],
			Name:  fields[2],
			Entry: fields[3],
		}
		out = append(out, sc)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan table: %w", err)
	}

	return out, nil
}

func ExtractSyscallName(fn string) string {
	if idx := strings.LastIndex(fn, "."); idx != -1 {
		return fn[idx+1:]
	}
	return fn
}

// ComputeRequiredCapabilities Given reachable syscalls and sysToCap mapping, compute required caps.
func ComputeRequiredCapabilities(cats *SyscallCategories, sysToCap map[string][]string) []string {
	requiredCaps := make(map[string]struct{})
	if cats == nil {
		return nil
	}

	// Normalize mapping keys once to avoid O(n^2) matching.
	sysToCapLower := make(map[string][]string, len(sysToCap))
	for name, caps := range sysToCap {
		sysToCapLower[strings.ToLower(name)] = caps
	}

	// 合并三个类别
	all := [][]string{
		cats.SyscallTraps,
		cats.SyscallWrappers,
		cats.SyscallRuntimes,
	}

	for _, group := range all {
		for _, fn := range group {

			syscallName := ExtractSyscallName(fn)
			syscallNameLower := strings.ToLower(syscallName)

			caps, ok := sysToCapLower[syscallNameLower]
			if !ok {
				continue
			}
			for _, c := range caps {
				requiredCaps[c] = struct{}{}
			}
		}
	}
	ret := make([]string, 0, len(requiredCaps))
	for req, _ := range requiredCaps {
		ret = append(ret, req)
	}
	return ret
}

// ComputeCanDropCaps returns the capabilities that are in default but NOT required.
// Returned slice is sorted and upper-cased.
func ComputeCanDropCaps(requiredCaps []string, defaultCaps map[string]struct{}) []string {
	_, canDrop, _ := deviation.DeviationAnalysis(requiredCaps, defaultCaps)
	sort.Strings(canDrop)
	return canDrop
}

func CalculateDeviation(requiredCaps []string) {
	// 读取 default caps (from your CSV)
	defaultCaps, err := deviation.LoadDefaultCaps("./input/default_caps.csv")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	needAdd, canDrop, intersection := deviation.DeviationAnalysis(requiredCaps, defaultCaps)

	fmt.Println("=== Required but NOT in default (need add:) ===")
	for _, c := range needAdd {
		fmt.Println("  -", c)
	}

	fmt.Println("\n=== In default but NOT required (can drop:) ===")
	for _, c := range canDrop {
		fmt.Println("  -", c)
	}

	fmt.Println("\n=== Required AND in default (OK to keep) ===")
	for _, c := range intersection {
		fmt.Println("  -", c)
	}
}

func printSet(c *SyscallCategories) {
	fmt.Println("\n--- [SyscallTraps] ---")
	for _, fn := range c.SyscallTraps {
		fmt.Println(fn)
	}

	fmt.Printf("\n--- [SyscallWrappers] Total=%d ---\n", len(c.SyscallWrappers))
	for i, fn := range c.SyscallWrappers {
		if i >= 10 {
			fmt.Println("... (others omitted)")
			break
		}
		fmt.Println(fn)
	}

	fmt.Println("\n--- [SyscallRuntimes] ---")
	for _, fn := range c.SyscallRuntimes {
		fmt.Println(fn)
	}
}
