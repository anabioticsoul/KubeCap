package mapping

import (
	"errors"
	"fmt"
	"go/constant"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

func uint64FromSSAConst(c *ssa.Const) (uint64, bool) {
	if c == nil || c.Value == nil {
		return 0, false
	}
	if c.Value.Kind() != constant.Int {
		return 0, false
	}
	if uv, ok := constant.Uint64Val(c.Value); ok {
		return uv, true
	}
	if iv, ok := constant.Int64Val(c.Value); ok {
		return uint64(iv), true
	}
	return 0, false
}

type ConditionalCapabilityAnalyzer struct {
	kb *KernelCapabilityKnowledgeBase
}

func NewConditionalCapabilityAnalyzer(kb *KernelCapabilityKnowledgeBase) *ConditionalCapabilityAnalyzer {
	return &ConditionalCapabilityAnalyzer{
		kb: kb,
	}
}

type SyscallCapabilityInfo struct {
	Syscall            string
	Capabilities       []string
	RequiredArgIndices []int
	IsConditional      bool
	ArgCondition       string
}

func (a *ConditionalCapabilityAnalyzer) ClassifySyscall(syscallName string) *SyscallCapabilityInfo {
	if a.kb == nil {
		return nil
	}

	rulesForSyscall := a.kb.BySyscall[syscallName]
	if len(rulesForSyscall) == 0 {
		return nil
	}

	info := &SyscallCapabilityInfo{
		Syscall:            syscallName,
		Capabilities:       []string{},
		RequiredArgIndices: []int{},
		IsConditional:      false,
	}

	capabilities := make(map[string]struct{}, 0)
	allArgIndices := make(map[int]struct{}, 0)

	for _, rule := range rulesForSyscall {
		for _, cap := range rule.Capability {
			capabilities[cap] = struct{}{}
		}

		if rule.ArgCondition != "true" && rule.ArgCondition != "" {
			info.IsConditional = true
			info.ArgCondition = rule.ArgCondition
			for _, argIdx := range rule.ArgIndices {
				allArgIndices[argIdx] = struct{}{}
			}
		}

		if rule.ExtraCondition != "true" && rule.ExtraCondition != "" && !strings.Contains(rule.ExtraCondition, "!capable") {
			info.IsConditional = true
		}
	}

	for cap := range capabilities {
		info.Capabilities = append(info.Capabilities, cap)
	}

	for argIdx := range allArgIndices {
		info.RequiredArgIndices = append(info.RequiredArgIndices, argIdx)
	}

	return info
}

type ConstantPropagationResult struct {
	Syscall       string
	Capability    string
	ArgIndex      int
	ConstantName  string
	ResolvedValue *uint64
	IsUnresolved  bool
	Error         string
}

// ConstantPropagation resolves constant values from ArgCondition by searching global constants
// Example: for "arg[1] == FLUSH_SCOPE_ALL", it extracts "FLUSH_SCOPE_ALL" and searches for its value
func (a *ConditionalCapabilityAnalyzer) ConstantPropagation(funs []*ssa.Function, syscall string, argIndex int, globalConstCache map[string]uint64) (*ConstantPropagationResult, error) {
	result := &ConstantPropagationResult{
		Syscall:      syscall,
		ArgIndex:     argIndex,
		IsUnresolved: true,
	}

	// Get the rule for this syscall to extract the constant name from ArgCondition
	rulesForSyscall := a.kb.BySyscall[syscall]
	if len(rulesForSyscall) == 0 {
		result.Error = fmt.Sprintf("no rules found for syscall %s", syscall)
		return result, errors.New(result.Error)
	}

	// Find the rule that mentions this argIndex
	var targetCondition string
	for _, rule := range rulesForSyscall {
		if rule.ArgCondition == "" || rule.ArgCondition == "true" {
			continue
		}
		// Check if this condition references the argIndex
		argRefPattern := fmt.Sprintf("arg[%d]", argIndex)
		if strings.Contains(rule.ArgCondition, argRefPattern) {
			targetCondition = rule.ArgCondition
			break
		}
	}

	if targetCondition == "" {
		result.Error = fmt.Sprintf("no condition found for %s arg[%d]", syscall, argIndex)
		return result, errors.New(result.Error)
	}

	// Try to extract constant name or numeric literal from condition
	// Case 1: Numeric literal like "arg[2] == 1"
	if numericVal := a.extractNumericLiteral(targetCondition); numericVal != nil {
		result.ResolvedValue = numericVal
		result.IsUnresolved = false
		return result, nil
	}

	// Case 2: Named constant like "arg[1] == FLUSH_SCOPE_ALL"
	constantName := a.extractConstantNameFromCondition(targetCondition)
	if constantName == "" {
		result.Error = fmt.Sprintf("no constant name or numeric value found in condition: %s", targetCondition)
		return result, errors.New(result.Error)
	}

	result.ConstantName = constantName

	// First check the global constant cache (from Stage 1 string search)
	if globalConstCache != nil {
		if cachedVal, found := globalConstCache[constantName]; found {
			result.ResolvedValue = &cachedVal
			result.IsUnresolved = false
			logMappingVerbose("Found constant %s from global cache: 0x%x", constantName, cachedVal)
			return result, nil
		}
	}

	// If not in cache, try to search constant from source files (global string matching)
	resolvedVal := a.searchGlobalConstantFromSource(constantName)
	if resolvedVal != nil {
		result.ResolvedValue = resolvedVal
		result.IsUnresolved = false
		logMappingVerbose("Found constant %s from source: 0x%x", constantName, *resolvedVal)
		return result, nil
	}

	// If not found from source, try SSA constant propagation analysis
	resolvedVal = a.findGlobalConstant(funs, constantName)
	if resolvedVal != nil {
		result.ResolvedValue = resolvedVal
		result.IsUnresolved = false
		return result, nil
	}

	result.Error = fmt.Sprintf("constant %s not found in global scope", constantName)
	return result, nil
}

// extractNumericLiteral extracts numeric literals from conditions like:
// "arg[2] == 1" -> 1
// "arg[0] > 3" -> 3
// Supports decimal and hexadecimal (0x prefix)
func (a *ConditionalCapabilityAnalyzer) extractNumericLiteral(condition string) *uint64 {
	condition = strings.ReplaceAll(condition, " ", "")

	// Patterns for numeric literals
	patterns := []string{
		`arg\[\d+\]==(0x[0-9a-fA-F]+)`, // arg[2] == 0x10
		`arg\[\d+\]==(\d+)`,            // arg[2] == 1
		`(0x[0-9a-fA-F]+)==arg\[\d+\]`, // 0x10 == arg[2]
		`(\d+)==arg\[\d+\]`,            // 1 == arg[2]
		`arg\[\d+\]>(0x[0-9a-fA-F]+)`,  // arg[0] > 0x3
		`arg\[\d+\]>(\d+)`,             // arg[0] > 3
		`arg\[\d+\]<(0x[0-9a-fA-F]+)`,  // arg[0] < 0x5
		`arg\[\d+\]<(\d+)`,             // arg[0] < 5
		`arg\[\d+\]&(0x[0-9a-fA-F]+)`,  // arg[1] & 0x80
		`arg\[\d+\]&(\d+)`,             // arg[1] & 128
		`arg\[\d+\]\|(0x[0-9a-fA-F]+)`, // arg[1] | 0x02
		`arg\[\d+\]\|(\d+)`,            // arg[1] | 2
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(condition)
		if len(matches) >= 2 {
			numStr := matches[1]
			var val uint64
			var err error

			if strings.HasPrefix(numStr, "0x") || strings.HasPrefix(numStr, "0X") {
				// Hexadecimal
				val, err = strconv.ParseUint(numStr[2:], 16, 64)
			} else {
				// Decimal
				val, err = strconv.ParseUint(numStr, 10, 64)
			}

			if err == nil {
				return &val
			}
		}
	}

	return nil
}

// extractConstantNameFromCondition extracts the constant name from conditions like:
// "arg[1] == FLUSH_SCOPE_ALL" -> "FLUSH_SCOPE_ALL"
// "arg[0] == RTC_PLL_SET" -> "RTC_PLL_SET"
// "arg[1] & SPU_CREATE_NOSCHED" -> "SPU_CREATE_NOSCHED"
func (a *ConditionalCapabilityAnalyzer) extractConstantNameFromCondition(condition string) string {
	// Remove spaces for easier parsing
	condition = strings.ReplaceAll(condition, " ", "")

	// Pattern to match constant names in conditions
	// Matches: arg[n] == NAME, arg[n] & NAME, arg[n] | NAME, etc.
	// Allow alphanumeric with underscores, not just uppercase
	patterns := []string{
		`arg\[\d+\]==([A-Za-z_][A-Za-z0-9_]*)`, // arg[1] == CONST
		`arg\[\d+\]&([A-Za-z_][A-Za-z0-9_]*)`,  // arg[1] & CONST
		`arg\[\d+\]\|([A-Za-z_][A-Za-z0-9_]*)`, // arg[1] | CONST
		`([A-Za-z_][A-Za-z0-9_]*)==arg\[\d+\]`, // CONST == arg[1]
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(condition)
		if len(matches) >= 2 {
			return matches[1]
		}
	}

	return ""
}

// searchGlobalConstantFromSource searches for a constant definition in source files using string matching
// This is especially useful for finding constants in zerrors_*.go files and other generated code
// Example: searches for "RTC_PLL_SET = 0x40207012" or "RTC_PLL_SET                          = 0x40207012"
func (a *ConditionalCapabilityAnalyzer) searchGlobalConstantFromSource(constantName string) *uint64 {
	// Try to find in common golang.org/x/sys/unix zerrors files
	possiblePaths := []string{
		// System-wide packages
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_amd64.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_arm64.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_arm.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_386.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_mips.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_ppc64.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_ppc64le.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_s390x.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_mips64.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_mips64le.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_mipsle.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_riscv64.go",
		"/usr/local/go/src/golang.org/x/sys/unix/zerrors_linux_sparc64.go",
	}

	// Try common GOPATH locations
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, arch := range []string{"amd64", "arm64", "arm", "386", "mips", "ppc64", "ppc64le", "s390x", "mips64", "mips64le", "mipsle", "riscv64", "sparc64"} {
			possiblePaths = append(possiblePaths,
				filepath.Join(gopath, "pkg/mod/golang.org/x/sys@*/unix", fmt.Sprintf("zerrors_linux_%s.go", arch)),
			)
		}
	}

	// Also try vendor directories in current working directory
	if cwd, err := os.Getwd(); err == nil {
		for _, arch := range []string{"amd64", "arm64", "arm", "386", "mips", "ppc64", "ppc64le", "s390x", "mips64", "mips64le", "mipsle", "riscv64", "sparc64"} {
			possiblePaths = append(possiblePaths,
				filepath.Join(cwd, "vendor/golang.org/x/sys/unix", fmt.Sprintf("zerrors_linux_%s.go", arch)),
			)
		}
		// Also check parent directories up to workspace root
		for i := 0; i < 5; i++ {
			parentDir := strings.Repeat("../", i)
			for _, arch := range []string{"amd64", "arm64", "arm", "386", "mips", "ppc64", "ppc64le", "s390x", "mips64", "mips64le", "mipsle", "riscv64", "sparc64"} {
				possiblePaths = append(possiblePaths,
					filepath.Join(cwd, parentDir, "vendor/golang.org/x/sys/unix", fmt.Sprintf("zerrors_linux_%s.go", arch)),
				)
			}
		}
	}

	// Pattern to match constant definitions with flexible spacing
	// Matches: "CONSTANT_NAME = 0x12345" or "CONSTANT_NAME                          = 0x12345"
	patterns := []string{
		fmt.Sprintf(`\b%s\s*=\s*(0x[0-9a-fA-F]+)\b`, regexp.QuoteMeta(constantName)),
		fmt.Sprintf(`const\s+%s\s*=\s*(0x[0-9a-fA-F]+)`, regexp.QuoteMeta(constantName)),
		fmt.Sprintf(`var\s+%s\s*=\s*(0x[0-9a-fA-F]+)`, regexp.QuoteMeta(constantName)),
	}

	for _, filePath := range possiblePaths {
		// Handle glob patterns by expanding them
		if strings.Contains(filePath, "*") {
			// Use filepath.Glob to expand patterns like vendor/golang.org/x/sys@*/unix
			pattern := filepath.Join(filepath.Dir(filePath), "*", filepath.Base(filepath.Dir(filePath)), filepath.Base(filePath))
			if matches, err := filepath.Glob(pattern); err == nil {
				for _, match := range matches {
					if val := a.searchConstantInFile(match, constantName, patterns); val != nil {
						return val
					}
				}
			}
		} else if val := a.searchConstantInFile(filePath, constantName, patterns); val != nil {
			return val
		}
	}

	// Search recursively through vendor directories
	if cwd, err := os.Getwd(); err == nil {
		vendorPath := filepath.Join(cwd, "vendor")
		if val := a.searchConstantInDirectory(vendorPath, constantName, patterns); val != nil {
			return val
		}

		// Also search in well-known parent directories
		// In case the cwd is a subdirectory of the workspace
		for i := 0; i < 5; i++ {
			parentPath := strings.Repeat("../", i)
			vendorPath := filepath.Join(cwd, parentPath, "vendor")
			if val := a.searchConstantInDirectory(vendorPath, constantName, patterns); val != nil {
				return val
			}
		}
	}

	return nil
}

// searchConstantInFile searches for a constant in a specific file
func (a *ConditionalCapabilityAnalyzer) searchConstantInFile(filePath string, constantName string, patterns []string) *uint64 {
	if filePath == "" {
		return nil
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil || fileInfo.IsDir() {
		return nil
	}

	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}

	return a.parseConstantFromContent(string(content), constantName, patterns)
}

// searchConstantInDirectory recursively searches for a constant in a directory
func (a *ConditionalCapabilityAnalyzer) searchConstantInDirectory(dirPath string, constantName string, patterns []string) *uint64 {
	return a.searchConstantInDirectoryWithDepth(dirPath, constantName, patterns, 0)
}

// searchConstantInDirectoryWithDepth recursively searches with depth tracking
func (a *ConditionalCapabilityAnalyzer) searchConstantInDirectoryWithDepth(dirPath string, constantName string, patterns []string, depth int) *uint64 {
	if dirPath == "" {
		return nil
	}

	// Limit search depth to avoid excessive recursion
	if depth > 15 {
		return nil
	}

	entries, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil
	}

	// First pass: prioritize zerrors files
	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())

		// Skip common non-relevant directories
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "__pycache__" || entry.Name() == "node_modules" || entry.Name() == ".vscode" {
				continue
			}
			continue
		}

		// Only process .go files
		if !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}

		// Prioritize zerrors files for efficiency
		if strings.HasPrefix(entry.Name(), "zerrors") {
			if val := a.searchConstantInFile(fullPath, constantName, patterns); val != nil {
				return val
			}
		}
	}

	// Second pass: search subdirectories
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Skip common non-relevant directories
		if entry.Name() == ".git" || entry.Name() == "__pycache__" || entry.Name() == "node_modules" || entry.Name() == ".vscode" {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		if val := a.searchConstantInDirectoryWithDepth(fullPath, constantName, patterns, depth+1); val != nil {
			return val
		}
	}

	// Third pass: search non-zerrors .go files
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasPrefix(entry.Name(), "zerrors") {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		if val := a.searchConstantInFile(fullPath, constantName, patterns); val != nil {
			return val
		}
	}

	return nil
}

// parseConstantFromContent searches for and parses a constant value from file content
func (a *ConditionalCapabilityAnalyzer) parseConstantFromContent(content string, constantName string, patterns []string) *uint64 {
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) >= 2 {
			numStr := matches[1]
			var val uint64
			var err error

			if strings.HasPrefix(numStr, "0x") || strings.HasPrefix(numStr, "0X") {
				val, err = strconv.ParseUint(numStr[2:], 16, 64)
			} else {
				val, err = strconv.ParseUint(numStr, 10, 64)
			}

			if err == nil {
				// Successfully found and parsed the constant
				// Note: Do not log here to avoid flooding output during recursive search
				return &val
			}
		}
	}

	return nil
}

// findGlobalConstant searches for a global constant by name across all packages
func (a *ConditionalCapabilityAnalyzer) findGlobalConstant(funs []*ssa.Function, constantName string) *uint64 {
	// Collect all unique packages from reachable functions (if available)
	packages := make(map[*ssa.Package]struct{})
	for _, f := range funs {
		if f.Pkg != nil {
			packages[f.Pkg] = struct{}{}
		}
	}

	// If we have no packages from functions, try to get SSA program from KB
	var ssaProgram *ssa.Program
	if len(packages) > 0 {
		for pkg := range packages {
			if pkg.Prog != nil {
				ssaProgram = pkg.Prog
				break
			}
		}
	} else {
		// Fallback: try to use KB's program if available
		// Note: KB loads from source, so it may have a program context
		if a.kb != nil && len(a.kb.Rules) > 0 {
			// We don't have direct access to KB's program, but we can search known packages
			logMappingDebug("No functions provided, will search system packages only for %s", constantName)
		}
	}

	// Search in direct packages and their imports using BFS
	searchedPackages := make(map[*ssa.Package]bool)
	packagesToSearch := make([]*ssa.Package, 0, len(packages))
	for pkg := range packages {
		packagesToSearch = append(packagesToSearch, pkg)
	}

	// BFS to search packages and their imports
	for len(packagesToSearch) > 0 {
		currentPkg := packagesToSearch[0]
		packagesToSearch = packagesToSearch[1:]

		if searchedPackages[currentPkg] {
			continue
		}
		searchedPackages[currentPkg] = true

		// Search in current package
		if result := searchPackageForConstant(currentPkg, constantName); result != nil {
			return result
		}

		// Add imported packages to search queue
		if currentPkg.Pkg != nil {
			for _, imp := range currentPkg.Pkg.Imports() {
				if ssaProgram != nil {
					if ssaPkg := ssaProgram.Package(imp); ssaPkg != nil {
						if !searchedPackages[ssaPkg] {
							packagesToSearch = append(packagesToSearch, ssaPkg)
						}
					}
				}
			}
		}
	}

	// If still not found, search commonly used system packages explicitly
	if ssaProgram != nil {
		systemPackages := []string{
			"syscall",
			"golang.org/x/sys/unix",
			"golang.org/x/sys/windows",
			"internal/syscall/unix",
		}

		for _, pkgPath := range systemPackages {
			// Try ImportedPackage first
			if pkg := ssaProgram.ImportedPackage(pkgPath); pkg != nil {
				if !searchedPackages[pkg] {
					if result := searchPackageForConstant(pkg, constantName); result != nil {
						return result
					}
				}
			}
		}

		// As a last resort, try to search through all loaded packages
		// This is a broad search but may be needed for edge cases
		if allPkgs := ssaProgram.AllPackages(); allPkgs != nil {
			for _, pkg := range allPkgs {
				if !searchedPackages[pkg] {
					if result := searchPackageForConstant(pkg, constantName); result != nil {
						return result
					}
				}
			}
		}
	} else if len(packages) == 0 {
		// No program available at all - this is a limitation
		logMappingWarn("No SSA program context available to search for constant %s", constantName)
	}

	return nil
}

// searchPackageForConstant searches for a constant in a specific package
func searchPackageForConstant(pkg *ssa.Package, constantName string) *uint64 {
	if pkg == nil {
		return nil
	}

	// Search in Members (direct declarations)
	for _, member := range pkg.Members {
		if namedConst, ok := member.(*ssa.NamedConst); ok {
			if namedConst.Name() == constantName {
				if val, ok := uint64FromSSAConst(namedConst.Value); ok {
					return &val
				}
			}
		}
	}

	return nil
}

func (a *ConditionalCapabilityAnalyzer) backtraceConstant(value ssa.Value, parentFunc *ssa.Function) *uint64 {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case *ssa.Const:
		if val, ok := uint64FromSSAConst(v); ok {
			return &val
		}
		return nil

	case *ssa.Phi:
		for _, edge := range v.Edges {
			if result := a.backtraceConstant(edge, parentFunc); result != nil {
				return result
			}
		}

	case ssa.Instruction:
		if parentFunc != nil && v.Parent() == parentFunc {
			switch vi := v.(type) {
			case *ssa.BinOp:
				leftVal := a.backtraceConstant(vi.X, parentFunc)
				rightVal := a.backtraceConstant(vi.Y, parentFunc)
				if leftVal != nil && rightVal != nil {
					opStr := vi.Op.String()
					return a.applyBinOp(opStr, leftVal, rightVal)
				}

			case *ssa.UnOp:
				operandVal := a.backtraceConstant(vi.X, parentFunc)
				if operandVal != nil {
					opStr := vi.Op.String()
					return a.applyUnOp(opStr, operandVal)
				}

			}
		}

	case *ssa.Parameter:

	}

	return nil
}

func (a *ConditionalCapabilityAnalyzer) applyBinOp(op string, left, right *uint64) *uint64 {
	if left == nil || right == nil {
		return nil
	}

	var result uint64
	switch op {
	case "+":
		result = *left + *right
	case "-":
		result = *left - *right
	case "*":
		result = *left * *right
	case "|":
		result = *left | *right
	case "&":
		result = *left & *right
	case "^":
		result = *left ^ *right
	case "<<":
		if *right < 64 {
			result = *left << *right
		}
	case ">>":
		if *right < 64 {
			result = *left >> *right
		}
	default:
		return nil
	}

	return &result
}

func (a *ConditionalCapabilityAnalyzer) applyUnOp(op string, operand *uint64) *uint64 {
	if operand == nil {
		return nil
	}

	switch op {
	case "!":
		if *operand == 0 {
			val := uint64(1)
			return &val
		}
		return nil

	case "-":
		val := uint64(-int64(*operand))
		return &val

	case "^":
		val := ^*operand
		return &val
	}

	return nil
}

func (a *ConditionalCapabilityAnalyzer) ExtractArgIndexFromCondition(condition string) []int {
	if condition == "" || condition == "true" {
		return nil
	}

	argRefRegexp := regexp.MustCompile(`arg\[(\d+)\]`)
	matches := argRefRegexp.FindAllStringSubmatch(condition, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		idx, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		seen[idx] = struct{}{}
	}

	indices := make([]int, 0, len(seen))
	for idx := range seen {
		indices = append(indices, idx)
	}

	return indices
}
