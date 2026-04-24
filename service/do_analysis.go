package service

// This file keeps service-level analysis workflows.
// Boundary with util:
//   - util: leaf computations and extractors
//   - service: analysis manager mutations and multi-step analysis orchestration

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	analysisconfig "github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/cmd/argot/dependencies"
	"github.com/awslabs/ar-go-tools/fake/analysis"
	"github.com/awslabs/ar-go-tools/fake/analysis/cg"
	"github.com/awslabs/ar-go-tools/fake/analysis/mapping"
	fakeconfig "github.com/awslabs/ar-go-tools/fake/config"
	"github.com/awslabs/ar-go-tools/fake/util"
	"gopkg.in/yaml.v3"

	naivereachability "github.com/awslabs/ar-go-tools/fake/reachability"
)

// normalizeAnalysisToolName normalizes the analysis tool name.
// Supported tools: "reachability", "dependencies", "render"
func normalizeAnalysisToolName(tool string) string {
	normalized := strings.ToLower(strings.TrimSpace(tool))
	if normalized == "" {
		return "reachability" // default tool
	}
	return normalized
}

func normalizeRenderAnalysisKind(kind string) string {
	normalized := strings.ToLower(strings.TrimSpace(kind))
	switch normalized {
	case "", "pointer", "cha", "rta", "vta":
		if normalized == "" {
			return "pointer"
		}
		return normalized
	default:
		return "pointer"
	}
}

func runReachabilityAnalysis(entrypoint string, config *fakeconfig.ExportConfig, manager *analysis.AnalysisManager) (map[string]interface{}, map[string]interface{}, error) {
	toolName := normalizeAnalysisToolName(config.ReachabilityTool)
	analysisInput := map[string]interface{}{
		"entrypoint": entrypoint,
		"tool":       toolName,
	}

	switch analysisconfig.ToolName(toolName) {
	case analysisconfig.ReachabilityTool, analysisconfig.NaiveReachabilityTool:
		args := make([]string, 0, 5)
		if config.LoaderNoInit {
			args = append(args, "-noinit")
		}
		if config.LoaderSuppressErrs {
			args = append(args, "-suppress-load-errors")
		}
		if config.LoaderQuiet {
			args = append(args, "-quiet-loader")
		}
		if config.Verbose {
			args = append(args, "-verbose")
		}
		args = append(args, entrypoint)
		analysisInput["flags"] = args

		flags, err := naivereachability.NewFlags(args)
		if err != nil {
			return nil, nil, fmt.Errorf("create reachability flags: %w", err)
		}
		if err := naivereachability.Run(flags, manager); err != nil {
			return nil, nil, fmt.Errorf("reachability analysis: %w", err)
		}

	case analysisconfig.DependenciesTool:
		depArgs := []string{"-stdlib", entrypoint}
		analysisInput["flags"] = depArgs
		depFlags, err := dependencies.NewFlags(depArgs)
		if err != nil {
			return nil, nil, fmt.Errorf("create dependencies flags: %w", err)
		}
		if err := dependencies.Run(depFlags); err != nil {
			return nil, nil, fmt.Errorf("dependencies analysis: %w", err)
		}

		// Dependencies does not populate the fake manager callgraph. Use reachability
		// fallback so dependencies and reachability paths both avoid pointer analysis.
		reachabilityFallbackArgs := make([]string, 0, 5)
		if config.LoaderNoInit {
			reachabilityFallbackArgs = append(reachabilityFallbackArgs, "-noinit")
		}
		if config.LoaderSuppressErrs {
			reachabilityFallbackArgs = append(reachabilityFallbackArgs, "-suppress-load-errors")
		}
		if config.LoaderQuiet {
			reachabilityFallbackArgs = append(reachabilityFallbackArgs, "-quiet-loader")
		}
		if config.Verbose {
			reachabilityFallbackArgs = append(reachabilityFallbackArgs, "-verbose")
		}
		reachabilityFallbackArgs = append(reachabilityFallbackArgs, entrypoint)
		analysisInput["reachability_fallback_flags"] = reachabilityFallbackArgs

		reachabilityFlags, err := naivereachability.NewFlags(reachabilityFallbackArgs)
		if err != nil {
			return nil, nil, fmt.Errorf("create reachability fallback flags: %w", err)
		}
		if err := naivereachability.Run(reachabilityFlags, manager); err != nil {
			return nil, nil, fmt.Errorf("reachability fallback after dependencies: %w", err)
		}

	case analysisconfig.RenderTool:
		renderAnalysis := normalizeRenderAnalysisKind(config.RenderAnalysis)
		renderArgs := []string{fmt.Sprintf("-analysis=%s", renderAnalysis), entrypoint}
		analysisInput["flags"] = renderArgs
		analysisInput["render_analysis"] = renderAnalysis
		renderFlags, err := cg.NewFlags(renderArgs)
		if err != nil {
			return nil, nil, fmt.Errorf("create render flags: %w", err)
		}
		if err := cg.Run(renderFlags, manager, config.EntrypointTimeout); err != nil {
			return nil, nil, fmt.Errorf("render analysis: %w", err)
		}

	default:
		return nil, nil, fmt.Errorf("unsupported analysis tool %q (allowed: reachability, dependencies, render)", toolName)
	}

	cgNodes := 0
	if manager.GetCG() != nil {
		cgNodes = len(manager.GetCG().Nodes)
	}
	// util.LogError("%d reachable functions", cgNodes)

	analysisOutput := map[string]interface{}{
		"tool":            toolName,
		"callgraph_nodes": cgNodes,
	}
	return analysisInput, analysisOutput, nil
}

type analysisPerfSample struct {
	Elapsed         time.Duration
	HeapAllocDelta  int64
	TotalAllocDelta uint64
	PeakHeapAlloc   uint64
	PeakHeapDelta   int64
	NumGCDelta      uint32
	Status          string
}

func measureEntrypointAnalysis(
	entrypoint string,
	manifestPathHint string,
	entrypointsFile string,
	config *fakeconfig.ExportConfig,
	manager *analysis.AnalysisManager,
	collectPeak bool,
) ([]string, analysisPerfSample, error) {
	var before runtime.MemStats
	var after runtime.MemStats
	runtime.ReadMemStats(&before)

	peakHeapAlloc := before.HeapAlloc
	var stopPeak chan struct{}
	var peakResult chan uint64
	if collectPeak {
		stopPeak = make(chan struct{})
		peakResult = make(chan uint64, 1)
		go func(initial uint64) {
			peak := initial
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					var snap runtime.MemStats
					runtime.ReadMemStats(&snap)
					if snap.HeapAlloc > peak {
						peak = snap.HeapAlloc
					}
				case <-stopPeak:
					var snap runtime.MemStats
					runtime.ReadMemStats(&snap)
					if snap.HeapAlloc > peak {
						peak = snap.HeapAlloc
					}
					peakResult <- peak
					return
				}
			}
		}(peakHeapAlloc)
	}

	start := time.Now()
	canDrop, err := ProcessEntrypointWithAnalysisSteps(entrypoint, manifestPathHint, entrypointsFile, config, manager)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if collectPeak {
		close(stopPeak)
		peakHeapAlloc = <-peakResult
	}
	if after.HeapAlloc > peakHeapAlloc {
		peakHeapAlloc = after.HeapAlloc
	}

	sample := analysisPerfSample{
		Elapsed:         elapsed,
		HeapAllocDelta:  int64(after.HeapAlloc) - int64(before.HeapAlloc),
		TotalAllocDelta: after.TotalAlloc - before.TotalAlloc,
		PeakHeapAlloc:   peakHeapAlloc,
		PeakHeapDelta:   int64(peakHeapAlloc) - int64(before.HeapAlloc),
		NumGCDelta:      after.NumGC - before.NumGC,
		Status:          "ok",
	}
	if err != nil {
		sample.Status = "failed"
		return nil, sample, err
	}
	return canDrop, sample, nil
}

func bytesToMiB(v int64) float64 {
	return float64(v) / 1024.0 / 1024.0
}

func bytesToMiBU(v uint64) float64 {
	return float64(v) / 1024.0 / 1024.0
}

func logPerfSample(entrypoint, toolLabel string, sample analysisPerfSample) {
	util.LogInfo(
		"[PERF] entrypoint=%s tool=%s status=%s elapsed_ms=%d heap_alloc_delta_mib=%.2f total_alloc_delta_mib=%.2f peak_heap_alloc_mib=%.2f peak_heap_delta_mib=%.2f gc_delta=%d",
		entrypoint,
		toolLabel,
		sample.Status,
		sample.Elapsed.Milliseconds(),
		bytesToMiB(sample.HeapAllocDelta),
		bytesToMiBU(sample.TotalAllocDelta),
		bytesToMiBU(sample.PeakHeapAlloc),
		bytesToMiB(sample.PeakHeapDelta),
		sample.NumGCDelta,
	)
}

func perfToolLabel(config *fakeconfig.ExportConfig) string {
	toolLabel := normalizeAnalysisToolName(config.ReachabilityTool)
	if toolLabel == "render" {
		toolLabel = fmt.Sprintf("render-%s", normalizeRenderAnalysisKind(config.RenderAnalysis))
	}
	return toolLabel
}

func perfCSVRow(entrypoint, toolLabel string, sample analysisPerfSample) []string {
	return []string{
		entrypoint,
		toolLabel,
		sample.Status,
		strconv.FormatInt(sample.Elapsed.Milliseconds(), 10),
		strconv.FormatFloat(bytesToMiB(sample.HeapAllocDelta), 'f', 4, 64),
		strconv.FormatFloat(bytesToMiBU(sample.TotalAllocDelta), 'f', 4, 64),
		strconv.FormatFloat(bytesToMiBU(sample.PeakHeapAlloc), 'f', 4, 64),
		strconv.FormatFloat(bytesToMiB(sample.PeakHeapDelta), 'f', 4, 64),
		strconv.FormatUint(uint64(sample.NumGCDelta), 10),
	}
}

func normalizeCapabilityName(raw string) string {
	capName := strings.TrimSpace(strings.ToUpper(raw))
	if capName == "" {
		return ""
	}
	if !strings.HasPrefix(capName, "CAP_") {
		capName = "CAP_" + capName
	}
	return capName
}

func copyCapSet(src map[string]struct{}) map[string]struct{} {
	dup := make(map[string]struct{}, len(src))
	for capName := range src {
		dup[capName] = struct{}{}
	}
	return dup
}

func yamlPathCandidates(baseDir, manifestHint string) []string {
	if baseDir == "" || manifestHint == "" {
		return nil
	}

	hint := filepath.Clean(strings.TrimPrefix(strings.TrimSpace(manifestHint), "./"))
	hasExt := strings.EqualFold(filepath.Ext(hint), ".yaml") || strings.EqualFold(filepath.Ext(hint), ".yml")

	seen := make(map[string]struct{})
	addCandidate := func(path string, out *[]string) {
		cleaned := filepath.Clean(path)
		if _, ok := seen[cleaned]; ok {
			return
		}
		seen[cleaned] = struct{}{}
		*out = append(*out, cleaned)
	}

	out := make([]string, 0, 12)
	addCandidate(filepath.Join(baseDir, hint), &out)
	addCandidate(filepath.Join(baseDir, "rendered", hint), &out)

	if hasExt {
		return out
	}

	addCandidate(filepath.Join(baseDir, hint+".yaml"), &out)
	addCandidate(filepath.Join(baseDir, hint+".yml"), &out)
	addCandidate(filepath.Join(baseDir, "rendered", hint+".yaml"), &out)
	addCandidate(filepath.Join(baseDir, "rendered", hint+".yml"), &out)
	addCandidate(filepath.Join(baseDir, hint, "rendered.yaml"), &out)
	addCandidate(filepath.Join(baseDir, hint, "rendered.yml"), &out)
	addCandidate(filepath.Join(baseDir, "rendered", hint, "rendered.yaml"), &out)
	addCandidate(filepath.Join(baseDir, "rendered", hint, "rendered.yml"), &out)
	return out
}

func resolveManifestPath(entrypointsFile, manifestHint string) (string, error) {
	if strings.TrimSpace(manifestHint) == "" {
		return "", nil
	}

	group := filepath.Base(filepath.Dir(entrypointsFile))
	project := strings.TrimSuffix(filepath.Base(entrypointsFile), filepath.Ext(entrypointsFile))
	renderedRoots := []string{filepath.Join("input", "rendered", group, project)}
	if strings.EqualFold(group, "aws") {
		renderedRoots = append([]string{filepath.Join("input", "rendered", "AWS", project)}, renderedRoots...)
	}
	fallbackRoots := projectSourceRoots(entrypointsFile)

	for _, renderedRoot := range renderedRoots {
		for _, candidate := range yamlPathCandidates(renderedRoot, manifestHint) {
			st, err := os.Stat(candidate)
			if err == nil && !st.IsDir() {
				return candidate, nil
			}
		}
	}

	for _, fallbackRoot := range fallbackRoots {
		for _, candidate := range yamlPathCandidates(fallbackRoot, manifestHint) {
			st, err := os.Stat(candidate)
			if err == nil && !st.IsDir() {
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("manifest not found for hint %q", manifestHint)
}

func projectSourceRoots(entrypointsFile string) []string {
	group := filepath.Base(filepath.Dir(entrypointsFile))
	project := strings.TrimSuffix(filepath.Base(entrypointsFile), filepath.Ext(entrypointsFile))

	roots := make([]string, 0, 3)
	if strings.EqualFold(group, "aws") {
		roots = append(roots, filepath.Join("target", "AWS", project))
	}
	roots = append(roots, filepath.Join("target", "OSS", group, project))
	roots = append(roots, filepath.Join("target", group, project))
	return roots
}

func projectCollectionRoots(entrypointsFile string) []string {
	entrypointsDir := filepath.Dir(entrypointsFile)
	group := filepath.Base(entrypointsDir)
	groupParent := filepath.Base(filepath.Dir(entrypointsDir))

	roots := make([]string, 0, 4)
	if strings.EqualFold(group, "aws") {
		roots = append(roots, filepath.Join("target", "AWS"))
	}
	// Add nested paths like target/OSS/Github_TOSEM if applicable
	if groupParent != "" && groupParent != "." {
		roots = append(roots, filepath.Join("target", groupParent, group))
	}
	// Also add flat paths as fallback
	roots = append(roots, filepath.Join("target", group))
	return roots
}

func resolveBaselineCaps(
	entrypoint string,
	manifestPathHint string,
	entrypointsFile string,
	defaultCaps map[string]struct{},
	verbose bool,
	logWarnings bool,
) (map[string]struct{}, string) {
	baselineCaps := defaultCaps
	baselineSource := "default"
	if strings.TrimSpace(manifestPathHint) == "" {
		return baselineCaps, baselineSource
	}

	resolvedManifestPath, resolveErr := resolveManifestPath(entrypointsFile, manifestPathHint)
	if resolveErr != nil {
		if verbose && logWarnings {
			util.LogWarn("manifest not found for %s (%s): %v", entrypoint, manifestPathHint, resolveErr)
		}
		return baselineCaps, baselineSource
	}

	capsFromManifest, hasConfiguredCaps, parseErr := loadCapsFromManifestOrDefault(resolvedManifestPath, defaultCaps)
	if parseErr != nil {
		if verbose && logWarnings {
			util.LogWarn("parse manifest capabilities failed for %s (%s): %v", entrypoint, resolvedManifestPath, parseErr)
		}
		return baselineCaps, baselineSource
	}

	if hasConfiguredCaps {
		baselineCaps = capsFromManifest
		baselineSource = resolvedManifestPath
	}

	return baselineCaps, baselineSource
}

func resolveEntrypointPath(entrypointsFile, entrypoint string) string {
	ep := strings.TrimSpace(entrypoint)
	if ep == "" {
		return ep
	}

	candidates := make([]string, 0, 6)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		candidates = append(candidates, v)
	}

	add(ep)
	if !filepath.IsAbs(ep) && !strings.HasPrefix(ep, "./") {
		add("./" + ep)
	}

	if !filepath.IsAbs(ep) {
		rel := strings.TrimPrefix(filepath.ToSlash(ep), "./")
		for _, root := range projectSourceRoots(entrypointsFile) {
			add(filepath.Join(root, rel))
		}
		for _, root := range projectCollectionRoots(entrypointsFile) {
			add(filepath.Join(root, rel))
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		norm := filepath.Clean(c)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		if st, err := os.Stat(norm); err == nil && !st.IsDir() {
			if !isExecutableMainFile(norm) {
				continue
			}
			if filepath.IsAbs(norm) {
				return filepath.ToSlash(norm)
			}
			if strings.HasPrefix(norm, "./") {
				return filepath.ToSlash(norm)
			}
			return "./" + filepath.ToSlash(norm)
		}
	}

	return ep
}

func isExecutableMainFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}

	// Debug: check if file exists before parsing
	st, statErr := os.Stat(path)
	if statErr != nil {
		// Log that file doesn't exist with more detail
		if os.IsNotExist(statErr) {
			// File doesn't exist - don't log at error level, just return false
		} else {
			// Other stat error - log it
			fmt.Fprintf(os.Stderr, "DEBUG: Stat error for %s: %v\n", path, statErr)
		}
		return false
	}
	if st.IsDir() {
		fmt.Fprintf(os.Stderr, "DEBUG: %s is a directory, not a file\n", path)
		return false
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Parse error for %s: %v\n", path, err)
		return false
	}
	if file == nil || file.Name == nil || file.Name.Name != "main" {
		if file != nil && file.Name != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: %s is package %s, not main\n", path, file.Name.Name)
		}
		return false
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != "main" {
			continue
		}
		if fd.Recv != nil {
			continue
		}
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

func discoverProjectFallbackEntrypoints(entrypointsFile string) []string {
	projectRoots := projectSourceRoots(entrypointsFile)

	out := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	appendUnique := func(v string) {
		if v == "" {
			return
		}
		key := filepath.ToSlash(filepath.Clean(v))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, "./"+key)
	}

	for _, projectRoot := range projectRoots {
		rootMain := filepath.Join(projectRoot, "main.go")
		if st, err := os.Stat(rootMain); err == nil && !st.IsDir() && isExecutableMainFile(rootMain) {
			appendUnique(rootMain)
		}
	}

	candidates := make([]string, 0, 8)
	for _, projectRoot := range projectRoots {
		_ = filepath.Walk(projectRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				base := filepath.Base(path)
				if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if isExecutableMainFile(path) {
				candidates = append(candidates, path)
			}
			return nil
		})
	}

	if len(candidates) == 0 {
		return out
	}
	sort.Strings(candidates)
	for _, c := range candidates {
		appendUnique(c)
	}
	return out
}

func toStringSlice(raw interface{}) []string {
	result := make([]string, 0)
	switch v := raw.(type) {
	case []string:
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					result = append(result, s)
				}
			}
		}
	case string:
		s := strings.TrimSpace(v)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func extractCapabilitiesDirectives(node interface{}, adds, drops map[string]struct{}, hasConfig *bool) {
	switch n := node.(type) {
	case map[string]interface{}:
		if capsRaw, ok := n["capabilities"]; ok {
			if capsMap, ok := capsRaw.(map[string]interface{}); ok {
				if addRaw, ok := capsMap["add"]; ok {
					*hasConfig = true
					for _, capName := range toStringSlice(addRaw) {
						norm := normalizeCapabilityName(capName)
						if norm != "" {
							adds[norm] = struct{}{}
						}
					}
				}
				if dropRaw, ok := capsMap["drop"]; ok {
					*hasConfig = true
					for _, capName := range toStringSlice(dropRaw) {
						norm := normalizeCapabilityName(capName)
						if norm != "" {
							drops[norm] = struct{}{}
						}
					}
				}
			}
		}
		for _, child := range n {
			extractCapabilitiesDirectives(child, adds, drops, hasConfig)
		}
	case []interface{}:
		for _, child := range n {
			extractCapabilitiesDirectives(child, adds, drops, hasConfig)
		}
	}
}

func loadCapsFromManifestOrDefault(manifestPath string, defaultCaps map[string]struct{}) (map[string]struct{}, bool, error) {
	if strings.TrimSpace(manifestPath) == "" {
		return defaultCaps, false, nil
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return defaultCaps, false, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	addSet := make(map[string]struct{})
	dropSet := make(map[string]struct{})
	hasConfiguredCaps := false

	for {
		var doc interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return defaultCaps, false, err
		}
		extractCapabilitiesDirectives(doc, addSet, dropSet, &hasConfiguredCaps)
	}

	if !hasConfiguredCaps {
		return defaultCaps, false, nil
	}

	configuredCaps := copyCapSet(defaultCaps)
	for dropCap := range dropSet {
		delete(configuredCaps, dropCap)
	}
	for addCap := range addSet {
		configuredCaps[addCap] = struct{}{}
	}

	return configuredCaps, true, nil
}

func countSyscallCategories(cats *util.SyscallCategories) int {
	if cats == nil {
		return 0
	}
	return len(cats.SyscallTraps) + len(cats.SyscallWrappers) + len(cats.SyscallRuntimes)
}

func toCapSet(caps []string) map[string]struct{} {
	set := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		name := strings.TrimSpace(cap)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	return set
}

func diffSet(a, b map[string]struct{}) []string {
	d := make([]string, 0)
	for k := range a {
		if _, ok := b[k]; !ok {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

func splitCaps(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinNormalizedCaps(caps []string) string {
	set := toCapSet(caps)
	if len(set) == 0 {
		return ""
	}

	ordered := make([]string, 0, len(set))
	for capName := range set {
		ordered = append(ordered, capName)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ";")
}

func joinCapsIfEnabled(enabled bool, caps []string) string {
	if !enabled {
		return ""
	}
	return joinNormalizedCaps(caps)
}

func methodStatus(enabled bool, status string) string {
	if enabled {
		return status
	}
	return "disabled"
}

func buildMinimizedOutputPaths(outFile string) map[string]string {
	baseName := strings.TrimSuffix(filepath.Base(outFile), filepath.Ext(outFile))
	minimizedDir := filepath.Join(filepath.Dir(outFile), "minimized")
	return map[string]string{
		"kubePM":   filepath.Join(minimizedDir, baseName+".kubePM.csv"),
		"Decap":    filepath.Join(minimizedDir, baseName+".Decap.csv"),
		"Lica":     filepath.Join(minimizedDir, baseName+".Lica.csv"),
		"llmDecap": filepath.Join(minimizedDir, baseName+".llmDecap.csv"),
		"llmLica":  filepath.Join(minimizedDir, baseName+".llmLica.csv"),
		"canDrop":  filepath.Join(minimizedDir, baseName+".can_drop.csv"),
	}
}

func normalizeEntrypointKey(raw string) string {
	key := strings.TrimSpace(raw)
	if key == "" {
		return ""
	}
	key = filepath.ToSlash(filepath.Clean(key))
	for strings.HasPrefix(key, "./") {
		key = strings.TrimPrefix(key, "./")
	}
	return key
}

func lookupTruthSet(truthByEntrypoint map[string]map[string]struct{}, entrypoint string) (map[string]struct{}, bool) {
	if len(truthByEntrypoint) == 0 {
		return nil, false
	}

	base := normalizeEntrypointKey(entrypoint)
	if base == "" {
		return nil, false
	}

	candidates := []string{base}
	if strings.HasPrefix(base, "target/") {
		candidates = append(candidates, "./"+base)
	}
	if idx := strings.Index(base, "target/"); idx > 0 {
		tail := base[idx:]
		candidates = append(candidates, tail, "./"+tail)
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		if truth, ok := truthByEntrypoint[c]; ok {
			return truth, true
		}
	}

	return nil, false
}

func writeDeviationRow(deviationWriter *csv.Writer, entrypoint string, kubePMCaps, decapCaps, licaCaps []string, status string) {
	if deviationWriter == nil {
		return
	}

	kubePMSet := toCapSet(kubePMCaps)
	decapSet := toCapSet(decapCaps)
	licaSet := toCapSet(licaCaps)

	_ = deviationWriter.Write([]string{
		entrypoint,
		strconv.Itoa(len(kubePMSet)),
		strconv.Itoa(len(decapSet)),
		strconv.Itoa(len(licaSet)),
		strings.Join(diffSet(kubePMSet, decapSet), ";"),
		strings.Join(diffSet(decapSet, kubePMSet), ";"),
		strings.Join(diffSet(kubePMSet, licaSet), ";"),
		strings.Join(diffSet(licaSet, kubePMSet), ";"),
		strings.Join(diffSet(decapSet, licaSet), ";"),
		strings.Join(diffSet(licaSet, decapSet), ";"),
		status,
	})
}

func writeAccuracyRows(
	accuracyWriter *csv.Writer,
	truthByEntrypoint map[string]map[string]struct{},
	entrypoint string,
	kubePMCaps, decapCaps, licaCaps, llmDecapCaps, llmLicaCaps []string,
	enableDecap bool,
	enableLica bool,
	enableLLMDecap bool,
	enableLLMLica bool,
	status string,
) {
	if accuracyWriter == nil {
		return
	}

	truthSet, truthFound := lookupTruthSet(truthByEntrypoint, entrypoint)
	methods := []struct {
		name string
		caps []string
	}{
		{name: "KubePM", caps: kubePMCaps},
	}
	if enableDecap {
		methods = append(methods, struct {
			name string
			caps []string
		}{name: "Decap", caps: decapCaps})
	}
	if enableLica {
		methods = append(methods, struct {
			name string
			caps []string
		}{name: "Lica", caps: licaCaps})
	}
	if enableLLMDecap {
		methods = append(methods, struct {
			name string
			caps []string
		}{name: "LLMDecap", caps: llmDecapCaps})
	}
	if enableLLMLica {
		methods = append(methods, struct {
			name string
			caps []string
		}{name: "LLMLica", caps: llmLicaCaps})
	}

	for _, m := range methods {
		predSet := toCapSet(m.caps)
		truthCount := ""
		tp := ""
		fp := ""
		fn := ""
		precision := ""
		recall := ""
		f1 := ""
		jaccard := ""
		missingCaps := ""
		overprivilegedCaps := ""

		if truthFound {
			tpN, fpN, fnN, p, r, f, j := evalAgainstTruth(predSet, truthSet)
			truthCount = strconv.Itoa(len(truthSet))
			tp = strconv.Itoa(tpN)
			fp = strconv.Itoa(fpN)
			fn = strconv.Itoa(fnN)
			precision = p
			recall = r
			f1 = f
			jaccard = j
			missingCaps = strings.Join(diffSet(truthSet, predSet), ";")
			overprivilegedCaps = strings.Join(diffSet(predSet, truthSet), ";")
		}

		_ = accuracyWriter.Write([]string{
			entrypoint,
			m.name,
			truthCount,
			strconv.Itoa(len(predSet)),
			tp,
			fp,
			fn,
			precision,
			recall,
			f1,
			jaccard,
			missingCaps,
			overprivilegedCaps,
			strconv.FormatBool(truthFound),
			status,
		})
	}
}

func loadGroundTruthCaps(path string) (map[string]map[string]struct{}, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	truth := make(map[string]map[string]struct{})
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		entry := normalizeEntrypointKey(row[0])
		if entry == "" {
			continue
		}
		caps := ""
		if len(row) > 1 {
			caps = row[1]
		}
		truth[entry] = toCapSet(splitCaps(caps))
	}
	return truth, nil
}

func fmtRatio(num, den int) string {
	if den == 0 {
		return "0.0000"
	}
	return fmt.Sprintf("%.4f", float64(num)/float64(den))
}

func evalAgainstTruth(pred, truth map[string]struct{}) (tp, fp, fn int, precision, recall, f1, jaccard string) {
	for cap := range pred {
		if _, ok := truth[cap]; ok {
			tp++
		} else {
			fp++
		}
	}
	for cap := range truth {
		if _, ok := pred[cap]; !ok {
			fn++
		}
	}
	precision = fmtRatio(tp, tp+fp)
	recall = fmtRatio(tp, tp+fn)
	if (2*tp + fp + fn) == 0 {
		f1 = "0.0000"
	} else {
		f1 = fmt.Sprintf("%.4f", float64(2*tp)/float64(2*tp+fp+fn))
	}
	if (tp + fp + fn) == 0 {
		jaccard = "0.0000"
	} else {
		jaccard = fmt.Sprintf("%.4f", float64(tp)/float64(tp+fp+fn))
	}
	return
}

// exportConditionalSysCapsToCsv exports conditional syscall→capability mappings to CSV
func exportConditionalSysCapsToCsv(conditionalMap map[string][]analysis.ConditionalCapability, outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write([]string{"syscall", "capability", "arg_condition", "extra_condition"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write data rows
	for syscall, caps := range conditionalMap {
		for _, cap := range caps {
			row := []string{
				syscall,
				cap.Capability,
				cap.ArgCondition,
				cap.ExtraCondition,
			}
			if err := w.Write(row); err != nil {
				return fmt.Errorf("write row: %w", err)
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}

	return nil
}

// exportUnconditionalSysCapsToCsv exports unconditional syscall→capability mappings to CSV
func exportUnconditionalSysCapsToCsv(unconditionalMap map[string][]string, outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write([]string{"syscall", "capability"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Write data rows
	for syscall, caps := range unconditionalMap {
		for _, cap := range caps {
			row := []string{syscall, cap}
			if err := w.Write(row); err != nil {
				return fmt.Errorf("write row: %w", err)
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}

	return nil
}

// buildSingleEntrySysToCaps combines unconditional syscall→cap mappings with
// dynamically calculated capabilities from constant propagation.
// Result: map[syscall] → union of unconditional caps + calculated caps
func buildSingleEntrySysToCaps(
	unconditionalMap map[string][]string,
	calculatedCaps map[string][]analysis.ConditionalCapability,
) map[string][]string {
	result := make(map[string][]string)

	// First, copy all unconditional mappings
	for syscall, caps := range unconditionalMap {
		result[syscall] = append([]string{}, caps...)
	}

	// Then, add capabilities discovered through constant propagation
	for syscall, condCaps := range calculatedCaps {
		capSet := make(map[string]struct{})

		// Add existing unconditional caps
		for _, cap := range result[syscall] {
			capSet[cap] = struct{}{}
		}

		// Add calculated caps (union over all conditions)
		for _, condCap := range condCaps {
			capSet[condCap.Capability] = struct{}{}
		}

		// Convert back to slice
		caps := make([]string, 0, len(capSet))
		for cap := range capSet {
			caps = append(caps, cap)
		}
		result[syscall] = caps
	}

	return result
}

// mergeSysToCapsUnion computes the union of two syscall→cap mappings.
// Used to aggregate single-entry results into project-level allSysToCaps.
func mergeSysToCapsUnion(
	existing map[string][]string,
	toAdd map[string][]string,
) map[string][]string {
	result := make(map[string][]string)

	// Copy all existing mappings
	for syscall, caps := range existing {
		result[syscall] = append([]string{}, caps...)
	}

	// Merge in new mappings (union)
	for syscall, newCaps := range toAdd {
		capSet := make(map[string]struct{})

		// Add existing caps for this syscall
		for _, cap := range result[syscall] {
			capSet[cap] = struct{}{}
		}

		// Add new caps
		for _, cap := range newCaps {
			capSet[cap] = struct{}{}
		}

		// Convert back to slice
		caps := make([]string, 0, len(capSet))
		for cap := range capSet {
			caps = append(caps, cap)
		}
		result[syscall] = caps
	}

	return result
}

func DoDumpSyscallFile(renewed bool, url string, DOCPath string, libPath string) error {

	out := DOCPath
	// 0. 如果本地已有缓存文件，直接复用
	if !renewed {
		if _, err := os.Stat(out); err == nil {
			util.LogInfo("unix syscall list already exists, use local cache: %s", out)
			return nil
		} else if !os.IsNotExist(err) {
			// 其它类型的错误（例如权限），直接报错
			return fmt.Errorf("stat %s error: %v\n", out, err)
		}
	}
	// 这里选用的是 Android 公共内核仓库里的一份 syscall_64.tbl。
	// 实际上 generate.go 也是读 Linux 内核源码里的同一类文件。
	syscallTableURL := url
	funcs := util.GetSyscallByDOC(syscallTableURL)
	util.DumpToFile(funcs, DOCPath)
	funcs = util.GetSyscallFromLibs(DOCPath)
	util.DumpToFile(funcs, libPath)
	return nil
}

// parseConstValue parses a constant value string (hex, octal, or decimal) and returns uint64
func parseConstValue(valueStr string) uint64 {
	valueStr = strings.TrimSpace(valueStr)

	var value uint64
	if strings.HasPrefix(valueStr, "0x") || strings.HasPrefix(valueStr, "0X") {
		// Hexadecimal
		val, _ := strconv.ParseUint(valueStr[2:], 16, 64)
		value = val
	} else if strings.HasPrefix(valueStr, "0o") || strings.HasPrefix(valueStr, "0O") {
		// Octal
		val, _ := strconv.ParseUint(valueStr[2:], 8, 64)
		value = val
	} else {
		// Decimal
		val, _ := strconv.ParseUint(valueStr, 10, 64)
		value = val
	}
	return value
}

// DoGlobalConstantSearchByString performs a two-stage constant resolution:
// Stage 1: String-based search - scans Go source files for constant definitions
// Stage 2: SSA-based propagation - deferred to entrypoint processing for unresolved constants
func DoGlobalConstantSearchByString(rootDirs []string, verbose bool) map[string]uint64 {
	resolvedConstants := make(map[string]uint64)
	fileCount := 0

	//   2. Block const: const ( NAME = VALUE ... )
	// Supports decimal, hex (0x), and octal (0o) formats
	singleConstPattern := regexp.MustCompile(`const\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|0o[0-7]+|\d+)`)
	blockConstPattern := regexp.MustCompile(`(\w+)\s*=\s*(0x[0-9a-fA-F]+|0o[0-7]+|\d+)`)

	for _, rootDir := range rootDirs {
		if verbose {
			util.LogInfo("Scanning %s for constant definitions", rootDir)
		}

		// Walk the directory tree looking for Go files
		filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip directories we don't care about
			// Note: We explicitly include vendor/ to find constants in golang.org/x/sys/unix/zerrors_*.go
			if info.IsDir() {
				base := filepath.Base(path)
				if base == "testdata" || strings.HasPrefix(base, ".") {
					return filepath.SkipDir
				}
				return nil
			}

			// Only process Go source files
			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			// Read file contents
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			fileCount++
			content := string(data)

			// Find single const definitions: const NAME = VALUE
			matches := singleConstPattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) >= 3 {
					resolvedConstants[match[1]] = parseConstValue(match[2])
					// Note: verbose logging removed to avoid flooding output with thousands of constants
				}
			}

			// Find const blocks: const ( ... )
			// Extract content between const ( and )
			constBlockRegex := regexp.MustCompile(`const\s*\(\s*([^)]+)\)`)
			blockMatches := constBlockRegex.FindAllStringSubmatch(content, -1)
			for _, blockMatch := range blockMatches {
				if len(blockMatch) >= 2 {
					blockContent := blockMatch[1]
					// Find all NAME = VALUE pairs within this block
					lineMatches := blockConstPattern.FindAllStringSubmatch(blockContent, -1)
					for _, lineMatch := range lineMatches {
						if len(lineMatch) >= 3 {
							name := strings.TrimSpace(lineMatch[1])
							// Skip assignment targets with commas or other syntax
							if name != "" && !strings.Contains(name, ",") && !strings.Contains(name, " ") {
								value := parseConstValue(lineMatch[2])
								resolvedConstants[name] = value
								// Note: verbose logging removed to avoid flooding output with thousands of constants
							}
						}
					}
				}
			}

			return nil
		})
	}

	if verbose {
		util.LogInfo("Global constant search found %d constants", len(resolvedConstants))
	}

	return resolvedConstants
}

func DoExtractReachableFunctions(manager *analysis.AnalysisManager) error {
	callGraph := manager.GetCG()
	if callGraph == nil {
		return fmt.Errorf("call graph is nil")
	}
	functions := util.ExtractReachableFunctionsFromCG(callGraph)
	if len(functions) == 0 {
		return fmt.Errorf("no reachable functions found")
	}
	manager.SetReachableFunctions(functions)
	return nil
}

func DoIdentifySyscallsFromReachableFunctions(pattern string, manager *analysis.AnalysisManager) error {
	funs := manager.GetReachableFunctions()
	syscallCategories, err := util.IdentifySyscallsFromReachableFunctions(pattern, funs)
	if err != nil {
		return err
	}
	manager.SetReachableSyscalls(syscallCategories)
	return nil
}

func DoLoadMappingFromFile(manager *analysis.AnalysisManager, filePath string) error {
	sysToCap, capToSys, err := mapping.LoadMappingFromFile(filePath)
	manager.SetSysToCap(sysToCap)
	manager.SetCapToSys(capToSys)
	return err
}

// DoLoadLicaMappingFromFile loads Lica paper's syscall→capability mapping from CSV
// Format: System calls,Capabilities (e.g., "linkat,CAP_DAC_READ_SEARCH")
func DoLoadLicaMappingFromFile(manager *analysis.AnalysisManager, filePath string) error {
	if filePath == "" {
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // Allow variable field count
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("read CSV: %w", err)
	}

	licaSysToCaps := make(map[string][]string)

	// Skip header row if it exists (check first row)
	startIdx := 0
	if len(records) > 0 && records[0][0] == "System calls" {
		startIdx = 1
	}

	// Process records
	for i := startIdx; i < len(records); i++ {
		if len(records[i]) < 2 {
			continue
		}

		syscalls := strings.TrimSpace(records[i][0])
		capsStr := strings.TrimSpace(records[i][1])

		if syscalls == "" || capsStr == "" {
			continue
		}

		// Parse syscalls (can be comma-separated)
		syscallList := strings.Split(syscalls, ",")
		// Parse capabilities (can be semicolon-separated)
		capList := strings.Split(capsStr, ";")

		// Clean up whitespace
		for j := range syscallList {
			syscallList[j] = strings.TrimSpace(syscallList[j])
		}
		for j := range capList {
			capList[j] = strings.TrimSpace(capList[j])
		}

		// Add mapping for each syscall
		for _, syscall := range syscallList {
			if syscall != "" {
				if existing, ok := licaSysToCaps[syscall]; ok {
					// Merge with existing capabilities (union)
					capSet := make(map[string]struct{})
					for _, c := range existing {
						capSet[c] = struct{}{}
					}
					for _, c := range capList {
						capSet[c] = struct{}{}
					}
					merged := make([]string, 0, len(capSet))
					for c := range capSet {
						merged = append(merged, c)
					}
					licaSysToCaps[syscall] = merged
				} else {
					licaSysToCaps[syscall] = capList
				}
			}
		}
	}

	manager.SetLicaSysToCaps(licaSysToCaps)
	return nil
}

// DoLoadKubePMUnconditionalMappingFromFile loads KubePM unconditional
// capability mapping from CSV.
// Format: capability,syscall1 syscall2 syscall3
func DoLoadKubePMUnconditionalMappingFromFile(manager *analysis.AnalysisManager, filePath string) error {
	if filePath == "" {
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("read CSV: %w", err)
	}

	sysToCapSet := make(map[string]map[string]struct{})
	for _, row := range records {
		if len(row) < 2 {
			continue
		}

		capName := normalizeCapabilityName(row[0])
		syscallsRaw := strings.TrimSpace(row[1])
		if capName == "" || syscallsRaw == "" {
			continue
		}

		// Best-effort header skip.
		if strings.EqualFold(capName, "CAPABILITY") || strings.EqualFold(strings.TrimSpace(row[0]), "capability") {
			continue
		}

		for _, syscallName := range strings.Fields(syscallsRaw) {
			syscallName = strings.TrimSpace(syscallName)
			if syscallName == "" {
				continue
			}
			if _, ok := sysToCapSet[syscallName]; !ok {
				sysToCapSet[syscallName] = make(map[string]struct{})
			}
			sysToCapSet[syscallName][capName] = struct{}{}
		}
	}

	kubePMSysToCaps := make(map[string][]string, len(sysToCapSet))
	for syscallName, capSet := range sysToCapSet {
		caps := make([]string, 0, len(capSet))
		for capName := range capSet {
			caps = append(caps, capName)
		}
		sort.Strings(caps)
		kubePMSysToCaps[syscallName] = caps
	}

	manager.SetUnconditionalSysToCaps(kubePMSysToCaps)
	return nil
}

func DoLoadDefaultCapsFromFile(manager *analysis.AnalysisManager, filePath string) error {
	defaultCaps, err := mapping.LoadDefaultCaps(filePath)
	if err != nil {
		return err
	}
	manager.SetDefaultCaps(defaultCaps)
	return nil
}

func buildKernelDemandSinksBySyscall(kb *mapping.KernelCapabilityKnowledgeBase) map[string][]analysis.KernelDemandSink {
	if kb == nil {
		return nil
	}

	bySyscall := make(map[string][]analysis.KernelDemandSink, len(kb.BySyscall))
	for syscallName := range kb.BySyscall {
		rawSinks := kb.GetDemandSinksBySyscall(syscallName)
		if len(rawSinks) == 0 {
			continue
		}

		converted := make([]analysis.KernelDemandSink, 0, len(rawSinks))
		for _, sink := range rawSinks {
			converted = append(converted, analysis.KernelDemandSink{
				Syscall:        sink.Syscall,
				Capability:     sink.Capability,
				ArgIndices:     append([]int(nil), sink.ArgIndices...),
				ArgCondition:   sink.ArgCondition,
				ExtraCondition: sink.ExtraCondition,
			})
		}
		bySyscall[syscallName] = converted
	}

	return bySyscall
}

func newEntrypointManager(baseManager *analysis.AnalysisManager) *analysis.AnalysisManager {
	manager := new(analysis.AnalysisManager)
	manager.Init()
	if baseManager != nil {
		seedEntrypointManagerStaticState(manager, baseManager)
	}
	return manager
}

// seedEntrypointManagerStaticState copies non-SSA runtime state from base manager
// into the entrypoint manager. This orchestration stays in service layer.
func seedEntrypointManagerStaticState(dst *analysis.AnalysisManager, src *analysis.AnalysisManager) {
	if dst == nil || src == nil {
		return
	}
	dst.SetKB(src.GetKB())
	dst.SetDefaultCaps(src.GetDefaultCaps())
	dst.SetSysToCap(src.GetSysToCap())
	dst.SetCapToSys(src.GetCapToSys())
	dst.SetLicaSysToCaps(src.GetLicaSysToCaps())
	dst.SetConditionalSysToCaps(src.GetConditionalSysToCaps())
	dst.SetUnconditionalSysToCaps(src.GetUnconditionalSysToCaps())
	dst.SetResolvedConstants(src.GetResolvedConstants())

	if kb, ok := src.GetKB().(*mapping.KernelCapabilityKnowledgeBase); ok && kb != nil {
		if len(dst.GetUnconditionalSysToCaps()) == 0 {
			_, unconditionalMap := mapping.ClassifyKBRules(kb)
			dst.SetUnconditionalSysToCaps(unconditionalMap)
		}
		dst.SetKernelDemandSinksBySyscall(buildKernelDemandSinksBySyscall(kb))
	}
}

// PrepareKernelState performs Stage A once and returns the seeded base manager
// with KB-derived state to be reused for all entrypoints.
// This is intended to run after Step 3 (global constant search) and before Step 4.
func PrepareKernelState(config *fakeconfig.ExportConfig) (*analysis.AnalysisManager, error) {
	if config == nil || !config.UseKernelRules || config.KernelCapRulesPath == "" {
		return nil, nil
	}
	util.LogStageInput(config.Verbose, "Stage A", map[string]interface{}{
		"kernel_rules":     config.KernelCapRulesPath,
		"use_kernel_rules": config.UseKernelRules,
	})

	kb, err := mapping.LoadKernelCapabilityKnowledgeBase(config.KernelCapRulesPath, mapping.DefaultKernelCapabilityRuleLoadOptions())
	if err != nil {
		return nil, fmt.Errorf("load kernel capability knowledge base: %w", err)
	}

	conditionalMap, unconditionalMap := mapping.ClassifyKBRules(kb)
	baseManager := new(analysis.AnalysisManager)
	baseManager.Init()
	baseManager.SetKB(kb)
	baseManager.SetConditionalSysToCaps(conditionalMap)
	baseManager.SetUnconditionalSysToCaps(unconditionalMap)
	baseManager.SetKernelDemandSinksBySyscall(buildKernelDemandSinksBySyscall(kb))

	// TODO: Export KubePM mappings to CSV files
	kubepmDir := "./input/KubePM"
	// if err := exportConditionalSysCapsToCsv(conditionalMap, filepath.Join(kubepmDir, "conditional_syscalls.csv")); err != nil {
	// 	util.LogWarn("Failed to export conditional syscalls: %v", err)
	// }
	// if err := exportUnconditionalSysCapsToCsv(unconditionalMap, filepath.Join(kubepmDir, "unconditional_syscalls.csv")); err != nil {
	// 	util.LogWarn("Failed to export unconditional syscalls: %v", err)
	// }

	// Import KubePM mappings from CSV files
	if err := DoLoadKubePMUnconditionalMappingFromFile(baseManager, filepath.Join(kubepmDir, "unconditional_syscalls.csv")); err != nil {
		return nil, fmt.Errorf("load kubepm unconditional mapping: %w", err)
	}
	unconditionalMap = baseManager.GetUnconditionalSysToCaps()

	util.LogStageOutput(config.Verbose, "Stage A", map[string]interface{}{
		"kb_rules":               len(kb.Rules),
		"conditional_syscalls":   len(conditionalMap),
		"unconditional_syscalls": len(unconditionalMap),
		"kubepm_export_dir":      kubepmDir,
	})

	return baseManager, nil
}

func DoHandleAllConditionalCaps(manager *analysis.AnalysisManager) {
	mapping.HandleAllConditionalCaps(manager)
}

// func DoComputeRequiredCapabilities(manager *analysis.AnalysisManager) error {
// 	requiredSyscalls := manager.GetReachableSyscalls()
// 	sysToCap := manager.GetSysToCap()

// 	requiredCaps := util.ComputeRequiredCapabilities(requiredSyscalls, sysToCap)
// 	if requiredCaps == nil {
// 		return fmt.Errorf("no required capabilities found")
// 	}
// 	manager.SetRequiredCaps(requiredCaps)
// 	return nil
// }

// func DoDeviationAnalysis(manager *analysis.AnalysisManager) {
// 	//print requiredCaps
// 	//fmt.Printf("Required %d Capabilities:\n", len(requiredCaps))
// 	//for _, caps := range requiredCaps {
// 	//	fmt.Println(caps)
// 	//}
// 	requiredCaps := manager.GetRequiredCaps()
// 	util.CalculateDeviation(requiredCaps)
// }

// DoExportCanDropCSVs processes entrypoints directory and exports can-drop capabilities.
// It handles directory traversal and delegates to ProcessEntrypointsFile for individual files.
// KB classification (ClassifyKBRules) is performed once here before the walk; only
// SSA-based constant propagation runs per-entrypoint inside ProcessEntrypointsFile.
func DoExportCanDropCSVs(
	entrypointsRoot string,
	outputRoot string,
	config *fakeconfig.ExportConfig,
	baseManager *analysis.AnalysisManager,
) (*fakeconfig.ExportStats, error) {
	util.LogStageInput(config != nil && config.Verbose, "Batch", map[string]interface{}{
		"entrypoints_root": entrypointsRoot,
		"output_root":      outputRoot,
		"use_kernel_rules": config.UseKernelRules,
	})

	absEntrypointsRoot, err := filepath.Abs(entrypointsRoot)
	if err != nil {
		return nil, fmt.Errorf("abs entrypoints root: %w", err)
	}

	absOutputRoot, err := filepath.Abs(outputRoot)
	if err != nil {
		return nil, fmt.Errorf("abs output root: %w", err)
	}

	entrypointsAnchor, err := filepath.Abs("./input/entrypoints")
	if err != nil {
		return nil, fmt.Errorf("abs entrypoints anchor: %w", err)
	}

	stats := &fakeconfig.ExportStats{}
	csvFiles := make([]string, 0)

	// Pass 1: discover all project CSV files first so we can report stable progress.
	err = filepath.Walk(absEntrypointsRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-CSV files
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".csv") {
			return nil
		}

		csvFiles = append(csvFiles, path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Strings(csvFiles)
	totalProjects := len(csvFiles)
	util.LogInfo("discovered %d projects", totalProjects)
	if err := ensureExecutionBucketDirs(absOutputRoot, entrypointsAnchor, csvFiles); err != nil && config.Verbose {
		util.LogWarn("prepare execution bucket dirs failed: %v", err)
	}
	projectSuccesses := make([]string, 0, totalProjects)
	projectFailures := make([]string, 0, totalProjects)
	projectEmpties := make([]string, 0, totalProjects)

	// Only OSS/Github outputs are redirected to a temp root to avoid polluting normal output.
	tmpOutputRoot := filepath.Join(os.TempDir(), "ar-go-tools-output")
	githubRelPrefix := "OSS/Github/"

	// Pass 2: process each project CSV file with explicit progress output.
	for idx, path := range csvFiles {
		// Compute output path and project ID
		rel, relErr := filepath.Rel(entrypointsAnchor, path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			rel, relErr = filepath.Rel(absEntrypointsRoot, path)
			if relErr != nil {
				return nil, relErr
			}
		}

		relSlash := filepath.ToSlash(rel)
		outRootForProject := absOutputRoot
		if strings.HasPrefix(relSlash, githubRelPrefix) {
			outRootForProject = tmpOutputRoot
			if config.Verbose {
				util.LogInfo("reroute OSS/Github output to temp root: %s", outRootForProject)
			}
		}

		outPath := filepath.Join(outRootForProject, rel)
		projectID := strings.TrimSuffix(rel, filepath.Ext(rel))
		donePath := outPath + ".done"

		util.LogInfo("(%d/%d) %s", idx+1, totalProjects, projectID)

		if config.ResumeCompleted {
			if outInfo, outErr := os.Stat(outPath); outErr == nil && !outInfo.IsDir() {
				if doneInfo, doneErr := os.Stat(donePath); doneErr == nil && !doneInfo.IsDir() {
					if config.Verbose {
						util.LogInfo("skip completed project: %s", projectID)
					}
					continue
				}
			}
		}

		failedBefore := stats.FailedEntrypoints
		emptyBefore := stats.EmptyFiles

		// Process this entrypoints file; pass pre-built KB state to avoid reloading per entrypoint.
		projectBucket := "good_execution"
		if err := ProcessEntrypointsFile(path, outPath, projectID, config, stats, baseManager); err != nil {
			if config.Verbose {
				util.LogError("%s: %v", path, err)
			}
			projectFailures = append(projectFailures, projectID)
			projectBucket = "bad_execution"
			_ = copyProjectOutputsToBucket(absOutputRoot, rel, outPath, projectBucket)
			continue
		}

		if stats.EmptyFiles > emptyBefore {
			projectEmpties = append(projectEmpties, projectID)
			projectBucket = "bad_execution"
		} else if stats.FailedEntrypoints > failedBefore {
			projectFailures = append(projectFailures, projectID)
			projectBucket = "bad_execution"
		} else {
			projectSuccesses = append(projectSuccesses, projectID)
			projectBucket = "good_execution"
		}

		if config.ResumeCompleted {
			marker := fmt.Sprintf("project=%s\nsource=%s\nfinished_at=%s\n", projectID, path, time.Now().Format(time.RFC3339))
			if writeErr := os.WriteFile(donePath, []byte(marker), 0o644); writeErr != nil && config.Verbose {
				util.LogWarn("write done marker failed for %s: %v", projectID, writeErr)
			}
		}

		if copyErr := copyProjectOutputsToBucket(absOutputRoot, rel, outPath, projectBucket); copyErr != nil && config.Verbose {
			util.LogWarn("copy project outputs to %s failed for %s: %v", projectBucket, projectID, copyErr)
		}
	}

	util.LogStageOutput(config != nil && config.Verbose, "Batch", map[string]interface{}{
		"total_entrypoints": stats.TotalEntrypoints,
		"failed":            stats.FailedEntrypoints,
		"empty_files":       stats.EmptyFiles,
		"with_data":         stats.SuccessWithData,
		"without_data":      stats.SuccessWithoutData,
		"projects_total":    totalProjects,
		"projects_success":  len(projectSuccesses),
		"projects_failed":   len(projectFailures),
		"projects_empty":    len(projectEmpties),
	})

	util.LogInfo("[PROJECT STATS] total=%d success=%d failed=%d empty=%d", totalProjects, len(projectSuccesses), len(projectFailures), len(projectEmpties))
	if len(projectFailures) > 0 {
		util.LogInfo("[PROJECT FAILED LIST] %s", strings.Join(projectFailures, ", "))
	}
	if len(projectSuccesses) > 0 {
		util.LogInfo("[PROJECT SUCCESS LIST] %s", strings.Join(projectSuccesses, ", "))
	}

	return stats, nil
}

// ProcessEntrypointsFile loads entrypoints from a CSV file and exports can-drop capabilities for each.
// The baseManager is seeded once during Stage A with KB and capability mappings;
// each entrypoint gets a fresh manager cloned from that base manager.
func ProcessEntrypointsFile(
	entrypointsFile,
	outFile,
	projectID string,
	config *fakeconfig.ExportConfig,
	stats *fakeconfig.ExportStats,
	baseManager *analysis.AnalysisManager,
) error {
	// Debug: log current working directory
	cwd, _ := os.Getwd()
	if config.Verbose {
		util.LogVerbose(true, "DEBUG: ProcessEntrypointsFile - cwd=%s, entrypointsFile=%s", cwd, entrypointsFile)
	}

	// Load entrypoints from CSV
	entries, err := util.LoadEntrypointRecords(entrypointsFile)
	if err != nil {
		return fmt.Errorf("load entrypoints: %w", err)
	}

	if len(entries) == 0 {
		if config.Verbose {
			util.LogInfo("%s: empty entrypoints file", entrypointsFile)
		}
		stats.EmptyFiles++
		return nil
	}

	// Create output directory and per-method minimized outputs
	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	minimizedPaths := buildMinimizedOutputPaths(outFile)
	if err := os.MkdirAll(filepath.Dir(minimizedPaths["kubePM"]), 0o755); err != nil {
		return fmt.Errorf("mkdir minimized: %w", err)
	}

	fKubePM, err := os.Create(minimizedPaths["kubePM"])
	if err != nil {
		return fmt.Errorf("create kubePM minimized output: %w", err)
	}
	defer fKubePM.Close()
	kubePMWriter := csv.NewWriter(fKubePM)
	defer kubePMWriter.Flush()
	_ = kubePMWriter.Write([]string{"entrypoint", "minimized_caps", "status"})

	fDecap, err := os.Create(minimizedPaths["Decap"])
	if err != nil {
		return fmt.Errorf("create Decap minimized output: %w", err)
	}
	defer fDecap.Close()
	decapWriter := csv.NewWriter(fDecap)
	defer decapWriter.Flush()
	_ = decapWriter.Write([]string{"entrypoint", "minimized_caps", "status"})

	fLica, err := os.Create(minimizedPaths["Lica"])
	if err != nil {
		return fmt.Errorf("create Lica minimized output: %w", err)
	}
	defer fLica.Close()
	licaWriter := csv.NewWriter(fLica)
	defer licaWriter.Flush()
	_ = licaWriter.Write([]string{"entrypoint", "minimized_caps", "status"})

	fLLMDecap, err := os.Create(minimizedPaths["llmDecap"])
	if err != nil {
		return fmt.Errorf("create LLMDecap minimized output: %w", err)
	}
	defer fLLMDecap.Close()
	llmDecapWriter := csv.NewWriter(fLLMDecap)
	defer llmDecapWriter.Flush()
	_ = llmDecapWriter.Write([]string{"entrypoint", "minimized_caps", "status"})

	fLLMLica, err := os.Create(minimizedPaths["llmLica"])
	if err != nil {
		return fmt.Errorf("create LLMLica minimized output: %w", err)
	}
	defer fLLMLica.Close()
	llmLicaWriter := csv.NewWriter(fLLMLica)
	defer llmLicaWriter.Flush()
	_ = llmLicaWriter.Write([]string{"entrypoint", "minimized_caps", "status"})

	fCanDrop, err := os.Create(minimizedPaths["canDrop"])
	if err != nil {
		return fmt.Errorf("create can-drop output: %w", err)
	}
	defer fCanDrop.Close()
	canDropWriter := csv.NewWriter(fCanDrop)
	defer canDropWriter.Flush()
	_ = canDropWriter.Write([]string{"entrypoint", "kubePM_can_drop", "decap_can_drop", "lica_can_drop", "status"})

	var truthByEntrypoint map[string]map[string]struct{}
	// NOTE: Temporarily disabled due to known issues in accuracy evaluation flow.
	// if config.EnableAccuracyEval && config.GroundTruthCapsCSV != "" {
	// 	truthByEntrypoint, err = loadGroundTruthCaps(config.GroundTruthCapsCSV)
	// 	if err != nil {
	// 		if config.WarnOnFailure {
	// 			util.LogWarn("load ground truth caps failed: %v", err)
	// 		} else {
	// 			return fmt.Errorf("load ground truth caps: %w", err)
	// 		}
	// 	}
	// }

	var deviationWriter *csv.Writer
	// NOTE: Temporarily disabled due to known issues in methods deviation output.
	// if config.EnableComparisons {
	// 	deviationPath := strings.TrimSuffix(outFile, ".csv") + ".methods_deviation.csv"
	// 	fd, createErr := os.Create(deviationPath)
	// 	if createErr != nil {
	// 		return fmt.Errorf("create deviation report: %w", createErr)
	// 	}
	// 	defer fd.Close()
	// 	deviationWriter = csv.NewWriter(fd)
	// 	defer deviationWriter.Flush()
	// 	_ = deviationWriter.Write([]string{
	// 		"entrypoint",
	// 		"kubePM_count",
	// 		"decap_count",
	// 		"lica_count",
	// 		"kubePM_only_vs_decap",
	// 		"decap_only_vs_kubePM",
	// 		"kubePM_only_vs_lica",
	// 		"lica_only_vs_kubePM",
	// 		"decap_only_vs_lica",
	// 		"lica_only_vs_decap",
	// 		"status",
	// 	})
	// }

	requiredCapsPath := strings.TrimSuffix(outFile, ".csv") + ".required_caps.csv"
	fr, createErr := os.Create(requiredCapsPath)
	if createErr != nil {
		return fmt.Errorf("create required caps report: %w", createErr)
	}
	defer fr.Close()
	requiredCapsWriter := csv.NewWriter(fr)
	defer requiredCapsWriter.Flush()
	_ = requiredCapsWriter.Write([]string{
		"entrypoint",
		"kubePM_required_caps",
		"decap_required_caps",
		"lica_required_caps",
		"llmDecap_required_caps",
		"llmLica_required_caps",
		"status",
	})

	var perfWriter *csv.Writer
	if config.EnablePerfMetrics {
		perfPath := strings.TrimSuffix(outFile, ".csv") + ".perf.csv"
		fp, perfCreateErr := os.Create(perfPath)
		if perfCreateErr != nil {
			return fmt.Errorf("create perf metrics report: %w", perfCreateErr)
		}
		defer fp.Close()
		perfWriter = csv.NewWriter(fp)
		defer perfWriter.Flush()
		_ = perfWriter.Write([]string{
			"entrypoint",
			"tool",
			"status",
			"elapsed_ms",
			"heap_alloc_delta_mib",
			"total_alloc_delta_mib",
			"peak_heap_alloc_mib",
			"peak_heap_delta_mib",
			"gc_delta",
		})
	}

	var accuracyWriter *csv.Writer
	// NOTE: Temporarily disabled due to known issues in accuracy output.
	// if config.EnableAccuracyEval {
	// 	accuracyPath := strings.TrimSuffix(outFile, ".csv") + ".accuracy.csv"
	// 	fa, createErr := os.Create(accuracyPath)
	// 	if createErr != nil {
	// 		return fmt.Errorf("create accuracy report: %w", createErr)
	// 	}
	// 	defer fa.Close()
	// 	accuracyWriter = csv.NewWriter(fa)
	// 	defer accuracyWriter.Flush()
	// 	_ = accuracyWriter.Write([]string{
	// 		"entrypoint",
	// 		"method",
	// 		"truth_count",
	// 		"pred_count",
	// 		"tp",
	// 		"fp",
	// 		"fn",
	// 		"precision",
	// 		"recall",
	// 		"f1",
	// 		"jaccard",
	// 		"missing_caps",
	// 		"overprivileged_caps",
	// 		"truth_found",
	// 		"status",
	// 	})
	// }

	// Reset project-level state for new project
	// This ensures each project processes with clean aggregation state
	baseManager.SetCalculatedCaps(make(map[string][]analysis.ConditionalCapability))
	baseManager.SetSingleEntrySysToCaps(make(map[string][]string))
	baseManager.SetAllSysToCaps(make(map[string][]string))
	baseManager.SetKubePMRequiredCaps(make([]string, 0))
	baseManager.SetDecapRequiredCaps(make([]string, 0))
	baseManager.SetLicaRequiredCaps(make([]string, 0))
	baseManager.SetLLMDecapRequiredCaps(make([]string, 0))
	baseManager.SetLLMLicaRequiredCaps(make([]string, 0))

	util.LogProjectHeader(config.Verbose, projectID)
	if config.Verbose {
		util.LogVerbose(true, "entrypoints_file=%s output_file=%s entries=%d", entrypointsFile, outFile, len(entries))
	}

	// Process each entrypoint with detailed analysis steps
	// Strict mode: always trust CSV-provided entrypoint (column 2) as analysis target.
	// Do not auto-fallback to discovered mains, to keep output aligned with input.
	processedEntrypoints := make(map[string]struct{}, len(entries))
	successCount := 0
	failureCount := 0
	duplicateCount := 0
	invalidCount := 0
	for entryIdx, entry := range entries {
		stats.TotalEntrypoints++
		manager := newEntrypointManager(baseManager)
		entrypoint := resolveEntrypointPath(entrypointsFile, entry.Entrypoint)
		util.LogInfo("(%d/%d) entrypoint: %s", entryIdx+1, len(entries), entrypoint)

		// Debug: check if executable main file check
		isExec1 := isExecutableMainFile(strings.TrimPrefix(entrypoint, "./"))
		isExec2 := isExecutableMainFile(entrypoint)
		if config.Verbose {
			util.LogVerbose(true, "DEBUG: checking executable main: path1=%s isExec1=%v, path2=%s isExec2=%v",
				strings.TrimPrefix(entrypoint, "./"), isExec1, entrypoint, isExec2)
		}

		if !isExec1 && !isExec2 {
			stats.FailedEntrypoints++
			invalidCount++
			if perfWriter != nil {
				_ = perfWriter.Write([]string{entry.Entrypoint, perfToolLabel(config), "invalid_entrypoint", "", "", "", "", "", ""})
			}
			if config.WarnOnFailure {
				util.LogWarn("invalid entrypoint (not package main/main()): %s", entry.Entrypoint)
			}
			util.LogInfo("DEBUG: entrypoint marked as invalid_entrypoint: %s", entrypoint)
			_ = kubePMWriter.Write([]string{entry.Entrypoint, "", "invalid_entrypoint"})
			_ = decapWriter.Write([]string{entry.Entrypoint, "", methodStatus(config.EnableDecap, "invalid_entrypoint")})
			_ = licaWriter.Write([]string{entry.Entrypoint, "", methodStatus(config.EnableLica, "invalid_entrypoint")})
			_ = llmDecapWriter.Write([]string{entry.Entrypoint, "", methodStatus(config.EnableLLMDecap, "invalid_entrypoint")})
			_ = llmLicaWriter.Write([]string{entry.Entrypoint, "", methodStatus(config.EnableLLMLica, "invalid_entrypoint")})
			_ = canDropWriter.Write([]string{entry.Entrypoint, "", "", "", "invalid_entrypoint"})
			_ = requiredCapsWriter.Write([]string{entry.Entrypoint, "", "", "", "", "", "invalid_entrypoint"})
			writeDeviationRow(deviationWriter, entry.Entrypoint, nil, nil, nil, "invalid_entrypoint")
			writeAccuracyRows(accuracyWriter, truthByEntrypoint, entry.Entrypoint, nil, nil, nil, nil, nil, config.EnableDecap, config.EnableLica, config.EnableLLMDecap, config.EnableLLMLica, "invalid_entrypoint")
			continue
		}

		// Use (entrypoint, manifestPath) pair as dedup key to allow same entrypoint with different manifests
		entrypointKey := filepath.ToSlash(filepath.Clean(entrypoint)) + "|" + filepath.ToSlash(filepath.Clean(entry.ManifestPath))
		if config.Verbose {
			util.LogVerbose(true, "DEBUG: dedup check - entrypoint=%s, manifest=%s, key=%s", entrypoint, entry.ManifestPath, entrypointKey)
		}
		if _, seen := processedEntrypoints[entrypointKey]; seen {
			duplicateCount++
			if perfWriter != nil {
				_ = perfWriter.Write([]string{entrypoint, perfToolLabel(config), "duplicate_entrypoint", "", "", "", "", "", ""})
			}
			_ = kubePMWriter.Write([]string{entrypoint, "", "duplicate_entrypoint"})
			_ = decapWriter.Write([]string{entrypoint, "", methodStatus(config.EnableDecap, "duplicate_entrypoint")})
			_ = licaWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLica, "duplicate_entrypoint")})
			_ = llmDecapWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLLMDecap, "duplicate_entrypoint")})
			_ = llmLicaWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLLMLica, "duplicate_entrypoint")})
			_ = canDropWriter.Write([]string{entrypoint, "", "", "", "duplicate_entrypoint"})
			_ = requiredCapsWriter.Write([]string{entrypoint, "", "", "", "", "", "duplicate_entrypoint"})
			writeDeviationRow(deviationWriter, entrypoint, nil, nil, nil, "duplicate_entrypoint")
			writeAccuracyRows(accuracyWriter, truthByEntrypoint, entrypoint, nil, nil, nil, nil, nil, config.EnableDecap, config.EnableLica, config.EnableLLMDecap, config.EnableLLMLica, "duplicate_entrypoint")
			continue
		}
		processedEntrypoints[entrypointKey] = struct{}{}

		// Run per-entrypoint SSA analysis (reachability + constant propagation).
		if config.Verbose {
			util.LogVerbose(true, "DEBUG: about to process entrypoint with analysis steps: %s, manifest=%s", entrypoint, entry.ManifestPath)
		}
		var canDrop []string
		var err error
		toolLabel := perfToolLabel(config)
		if config.EnablePerfMetrics {
			var perfSample analysisPerfSample
			canDrop, perfSample, err = measureEntrypointAnalysis(entrypoint, entry.ManifestPath, entrypointsFile, config, manager, true)
			if err != nil {
				perfSample.Status = classifyEntrypointFailure(err)
			}
			logPerfSample(entrypoint, toolLabel, perfSample)
			if perfWriter != nil {
				_ = perfWriter.Write(perfCSVRow(entrypoint, toolLabel, perfSample))
			}
		} else {
			canDrop, err = ProcessEntrypointWithAnalysisSteps(entrypoint, entry.ManifestPath, entrypointsFile, config, manager)
		}
		if config.Verbose {
			util.LogVerbose(true, "DEBUG: completed entrypoint analysis, err=%v, canDrop count=%d", err, len(canDrop))
		}
		if err != nil {
			failureStatus := classifyEntrypointFailure(err)
			failureCount++
			stats.FailedEntrypoints++
			util.LogInfo("entrypoint FAILED: %s - status=%s, err=%v", entrypoint, failureStatus, err)
			if config.WarnOnFailure {
				util.LogWarn("%s: %v", entrypoint, err)
			}
			errKubePM := kubePMWriter.Write([]string{entrypoint, "", failureStatus})
			errDecap := decapWriter.Write([]string{entrypoint, "", methodStatus(config.EnableDecap, failureStatus)})
			errLica := licaWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLica, failureStatus)})
			errLLMDecap := llmDecapWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLLMDecap, failureStatus)})
			errLLMLica := llmLicaWriter.Write([]string{entrypoint, "", methodStatus(config.EnableLLMLica, failureStatus)})
			errCanDrop := canDropWriter.Write([]string{entrypoint, "", "", "", failureStatus})
			errReqCaps := requiredCapsWriter.Write([]string{entrypoint, "", "", "", "", "", failureStatus})
			if errKubePM != nil || errDecap != nil || errLica != nil || errLLMDecap != nil || errLLMLica != nil || errCanDrop != nil || errReqCaps != nil {
				util.LogWarn("failed to write failure status for %s: kubePM=%v decap=%v lica=%v llmDecap=%v llmLica=%v canDrop=%v reqCaps=%v",
					entrypoint, errKubePM, errDecap, errLica, errLLMDecap, errLLMLica, errCanDrop, errReqCaps)
			}
			writeDeviationRow(deviationWriter, entrypoint, nil, nil, nil, failureStatus)
			writeAccuracyRows(accuracyWriter, truthByEntrypoint, entrypoint, nil, nil, nil, nil, nil, config.EnableDecap, config.EnableLica, config.EnableLLMDecap, config.EnableLLMLica, failureStatus)
			continue
		}

		// Resolved constants are written directly into the shared global cache.

		// Count results
		if len(canDrop) > 0 {
			stats.SuccessWithData++
		} else {
			stats.SuccessWithoutData++
		}
		successCount++
		util.LogInfo("entrypoint SUCCESS: %s", entrypoint)

		baselineCaps, _ := resolveBaselineCaps(
			entrypoint,
			entry.ManifestPath,
			entrypointsFile,
			manager.GetDefaultCaps(),
			config.Verbose,
			false,
		)
		decapCanDrop := []string{}
		licaCanDrop := []string{}
		if config.EnableDecap {
			decapCanDrop = util.ComputeCanDropCaps(manager.GetDecapRequiredCaps(), baselineCaps)
		}
		if config.EnableLica {
			licaCanDrop = util.ComputeCanDropCaps(manager.GetLicaRequiredCaps(), baselineCaps)
		}

		_ = kubePMWriter.Write([]string{entrypoint, joinNormalizedCaps(manager.GetKubePMRequiredCaps()), "ok"})
		_ = decapWriter.Write([]string{entrypoint, joinCapsIfEnabled(config.EnableDecap, manager.GetDecapRequiredCaps()), methodStatus(config.EnableDecap, "ok")})
		_ = licaWriter.Write([]string{entrypoint, joinCapsIfEnabled(config.EnableLica, manager.GetLicaRequiredCaps()), methodStatus(config.EnableLica, "ok")})
		_ = llmDecapWriter.Write([]string{entrypoint, joinCapsIfEnabled(config.EnableLLMDecap, manager.GetLLMDecapRequiredCaps()), methodStatus(config.EnableLLMDecap, "ok")})
		_ = llmLicaWriter.Write([]string{entrypoint, joinCapsIfEnabled(config.EnableLLMLica, manager.GetLLMLicaRequiredCaps()), methodStatus(config.EnableLLMLica, "ok")})
		_ = canDropWriter.Write([]string{
			entrypoint,
			strings.Join(canDrop, ";"),
			joinCapsIfEnabled(config.EnableDecap, decapCanDrop),
			joinCapsIfEnabled(config.EnableLica, licaCanDrop),
			"ok",
		})
		_ = requiredCapsWriter.Write([]string{
			entrypoint,
			joinNormalizedCaps(manager.GetKubePMRequiredCaps()),
			joinCapsIfEnabled(config.EnableDecap, manager.GetDecapRequiredCaps()),
			joinCapsIfEnabled(config.EnableLica, manager.GetLicaRequiredCaps()),
			joinCapsIfEnabled(config.EnableLLMDecap, manager.GetLLMDecapRequiredCaps()),
			joinCapsIfEnabled(config.EnableLLMLica, manager.GetLLMLicaRequiredCaps()),
			"ok",
		})

		var decapCapsForReports []string
		if config.EnableDecap {
			decapCapsForReports = manager.GetDecapRequiredCaps()
		}
		var licaCapsForReports []string
		if config.EnableLica {
			licaCapsForReports = manager.GetLicaRequiredCaps()
		}

		writeDeviationRow(
			deviationWriter,
			entrypoint,
			manager.GetKubePMRequiredCaps(),
			decapCapsForReports,
			licaCapsForReports,
			"ok",
		)

		writeAccuracyRows(
			accuracyWriter,
			truthByEntrypoint,
			entrypoint,
			manager.GetKubePMRequiredCaps(),
			manager.GetDecapRequiredCaps(),
			manager.GetLicaRequiredCaps(),
			manager.GetLLMDecapRequiredCaps(),
			manager.GetLLMLicaRequiredCaps(),
			config.EnableDecap,
			config.EnableLica,
			config.EnableLLMDecap,
			config.EnableLLMLica,
			"ok",
		)
	}

	util.LogProjectFooter(config.Verbose)
	util.LogInfo("Project processing summary: success=%d failure=%d duplicate=%d invalid=%d", successCount, failureCount, duplicateCount, invalidCount)

	kubePMWriter.Flush()
	if err := kubePMWriter.Error(); err != nil {
		util.LogError("kubePMWriter flush error: %v", err)
		return err
	}
	decapWriter.Flush()
	if err := decapWriter.Error(); err != nil {
		util.LogError("decapWriter flush error: %v", err)
		return err
	}
	licaWriter.Flush()
	if err := licaWriter.Error(); err != nil {
		return err
	}
	llmDecapWriter.Flush()
	if err := llmDecapWriter.Error(); err != nil {
		return err
	}
	llmLicaWriter.Flush()
	if err := llmLicaWriter.Error(); err != nil {
		return err
	}
	canDropWriter.Flush()
	if err := canDropWriter.Error(); err != nil {
		return err
	}

	// NOTE: methods_deviation and accuracy outputs are temporarily disabled.
	// if deviationWriter != nil {
	// 	deviationWriter.Flush()
	// 	if err := deviationWriter.Error(); err != nil {
	// 		return err
	// 	}
	// }

	// if accuracyWriter != nil {
	// 	accuracyWriter.Flush()
	// 	if err := accuracyWriter.Error(); err != nil {
	// 		return err
	// 	}
	// }

	requiredCapsWriter.Flush()
	if err := requiredCapsWriter.Error(); err != nil {
		return err
	}

	if perfWriter != nil {
		perfWriter.Flush()
		if err := perfWriter.Error(); err != nil {
			return err
		}
	}

	return nil
}

// ProcessEntrypointWithAnalysisSteps returns the can-drop capabilities for a single entrypoint.
// The manager must already be pre-seeded with global KB results (conditionalSysToCaps,
// unconditionalSysToCaps, kernelDemandSinks, and KB) before this is called.
//
// Steps:
// 1. Run reachability analysis (builds SSA per-entrypoint)
// 2. Extract reachable functions
// 3. Per-entrypoint SSA constant propagation (PropagateConstantsWithKB, or HandleAllConditionalCaps)
// 4. Identify syscalls from reachable functions
// 5. Compute required capabilities
// 6. Compute can-drop capabilities
func ProcessEntrypointWithAnalysisSteps(
	entrypoint string,
	manifestPathHint string,
	entrypointsFile string,
	config *fakeconfig.ExportConfig,
	manager *analysis.AnalysisManager,
) ([]string, error) {
	// Step 1: Run selected entrypoint analysis tool.
	analysisInput, analysisOutput, err := runReachabilityAnalysis(entrypoint, config, manager)
	if err != nil {
		return nil, err
	}
	util.LogStepIO(config.Verbose, "reachability analysis", analysisInput, analysisOutput)

	// Step 2: Extract reachable functions from call graph
	functionExtractionInput := map[string]interface{}{"reachable_functions_cached": manager.GetReachableFunctions() != nil}
	if manager.GetReachableFunctions() == nil {
		if err := DoExtractReachableFunctions(manager); err != nil {
			return nil, err
		}
	}
	util.LogStepIO(config.Verbose, "function extraction", functionExtractionInput, map[string]interface{}{"reachable_functions": len(manager.GetReachableFunctions())})

	// Step 3: Per-entrypoint SSA-based constant propagation with conditional capability handling
	DoHandleAllConditionalCaps(manager)
	// constantPropagationInput := map[string]interface{}{
	// 	"use_kernel_rules":     config.UseKernelRules,
	// 	"has_kb":               manager.GetKB() != nil,
	// 	"conditional_syscalls": len(manager.GetConditionalSysToCaps()),
	// 	"resolved_constants":   len(manager.GetResolvedConstants()),
	// }

	// mapping.SetSpecialHandlerVerbose(config.Verbose)
	// if config.UseKernelRules && manager.GetKB() != nil {
	// 	kb := manager.GetKB().(*mapping.KernelCapabilityKnowledgeBase)
	// 	if err := mapping.PropagateConstantsWithKB(manager, kb, manager); err != nil {
	// 		if config.Verbose {
	// 			util.LogWarn("constant propagation failed: %v", err)
	// 		}
	// 	}
	// } else {
	// 	DoHandleAllConditionalCaps(manager)
	// }
	// util.LogStepIO(config.Verbose, "constant propagation", constantPropagationInput, map[string]interface{}{"resolved_constants": len(manager.GetResolvedConstants())})

	// Step 4: Identify all reachable syscalls from analyzed functions
	syscallIdentificationInput := map[string]interface{}{"reachable_functions": len(manager.GetReachableFunctions())}
	if err := DoIdentifySyscallsFromReachableFunctions("", manager); err != nil {
		return nil, err
	}
	reachableSyscalls := manager.GetReachableSyscalls()
	traps := 0
	wrappers := 0
	runtimes := 0
	if reachableSyscalls != nil {
		traps = len(reachableSyscalls.SyscallTraps)
		wrappers = len(reachableSyscalls.SyscallWrappers)
		runtimes = len(reachableSyscalls.SyscallRuntimes)
	}
	util.LogStepIO(config.Verbose, "syscall identification", syscallIdentificationInput, map[string]interface{}{
		"syscalls_total": countSyscallCategories(reachableSyscalls),
		"traps":          traps,
		"wrappers":       wrappers,
		"runtimes":       runtimes,
	})

	// Step 5: Compute required capabilities
	requiredSyscalls := manager.GetReachableSyscalls()
	capabilityComputationInput := map[string]interface{}{"syscalls_total": countSyscallCategories(requiredSyscalls)}

	// Build single entry mapping: unconditionalSysToCaps + calculatedCaps from constant propagation
	singleEntrySysToCaps := buildSingleEntrySysToCaps(
		manager.GetUnconditionalSysToCaps(),
		manager.GetCalculatedCaps(),
	)
	manager.SetSingleEntrySysToCaps(singleEntrySysToCaps)

	// Approach 1: KubePM（基于 singleEntrySysToCaps，即 unconditional + calculated）
	requiredCaps := util.ComputeRequiredCapabilities(requiredSyscalls, singleEntrySysToCaps)
	manager.SetKubePMRequiredCaps(requiredCaps)

	DecapRequiredCaps := []string{}
	if config.EnableDecap {
		// Approach 2: Decap（基于静态cap2syscall映射）
		DecapRequiredCaps = util.ComputeRequiredCapabilities(requiredSyscalls, manager.GetSysToCap())
	}
	manager.SetDecapRequiredCaps(DecapRequiredCaps)

	LicaRequiredCaps := []string{}
	if config.EnableLica {
		// Approach 3: Lica（基于逐个系统调用到能力的映射）
		LicaRequiredCaps = util.ComputeRequiredCapabilities(requiredSyscalls, manager.GetLicaSysToCaps())
	}
	manager.SetLicaRequiredCaps(LicaRequiredCaps)

	llmDecapRequiredCaps := []string{}
	if config.EnableLLMDecap {
		llmDecapSysToCaps := buildSingleEntrySysToCaps(manager.GetSysToCap(), manager.GetCalculatedCaps())
		llmDecapRequiredCaps = util.ComputeRequiredCapabilities(requiredSyscalls, llmDecapSysToCaps)
	}
	manager.SetLLMDecapRequiredCaps(llmDecapRequiredCaps)

	llmLicaRequiredCaps := []string{}
	if config.EnableLLMLica {
		llmLicaSysToCaps := buildSingleEntrySysToCaps(manager.GetLicaSysToCaps(), manager.GetCalculatedCaps())
		llmLicaRequiredCaps = util.ComputeRequiredCapabilities(requiredSyscalls, llmLicaSysToCaps)
	}
	manager.SetLLMLicaRequiredCaps(llmLicaRequiredCaps)

	// Aggregate into allSysToCaps (union of all entries in this project)
	allSysToCaps := mergeSysToCapsUnion(manager.GetAllSysToCaps(), singleEntrySysToCaps)
	manager.SetAllSysToCaps(allSysToCaps)

	util.LogStepIO(config.Verbose, "capability computation", capabilityComputationInput, map[string]interface{}{
		"required_caps_kubePM":   len(requiredCaps),
		"decap_enabled":          config.EnableDecap,
		"required_caps_Decap":    len(DecapRequiredCaps),
		"lica_enabled":           config.EnableLica,
		"required_caps_Lica":     len(LicaRequiredCaps),
		"llm_decap_enabled":      config.EnableLLMDecap,
		"required_caps_LLMDecap": len(llmDecapRequiredCaps),
		"llm_lica_enabled":       config.EnableLLMLica,
		"required_caps_LLMLica":  len(llmLicaRequiredCaps),
		"calculated_syscalls":    len(manager.GetCalculatedCaps()),
		"single_entry_syscalls":  len(singleEntrySysToCaps),
		"all_syscalls_so_far":    len(allSysToCaps),
	})

	// Step 6: Compute drop-able capabilities (in default but not required)
	baselineCaps, baselineSource := resolveBaselineCaps(
		entrypoint,
		manifestPathHint,
		entrypointsFile,
		manager.GetDefaultCaps(),
		config.Verbose,
		true,
	)

	dropCapabilityInput := map[string]interface{}{
		"required_caps":     len(requiredCaps),
		"baseline_caps":     len(baselineCaps),
		"baseline_caps_src": baselineSource,
	}
	canDrop := util.ComputeCanDropCaps(requiredCaps, baselineCaps)
	util.LogStepIO(config.Verbose, "drop-able capability analysis", dropCapabilityInput, map[string]interface{}{"can_drop": len(canDrop)})
	return canDrop, nil
}

func classifyEntrypointFailure(err error) string {
	if err == nil {
		return "analysis_failed"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timed out") || strings.Contains(msg, "timeout") {
		return "timeout"
	}
	if strings.Contains(msg, "failed to build program") || strings.Contains(msg, "errors found") {
		return "build_failed"
	}
	return "analysis_failed"
}

func copyProjectOutputsToBucket(absOutputRoot, rel, outPath, bucket string) error {
	relSlash := filepath.ToSlash(rel)
	bucketRoot := filepath.Join(absOutputRoot, bucket)
	relForBucket := rel
	if strings.HasPrefix(relSlash, "OSS/") {
		bucketRoot = filepath.Join(absOutputRoot, "OSS", bucket)
		relForBucket = filepath.FromSlash(strings.TrimPrefix(relSlash, "OSS/"))
	}

	destMain := filepath.Join(bucketRoot, relForBucket)
	if err := copyFileIfExists(outPath, destMain); err != nil {
		return err
	}

	srcMinimized := buildMinimizedOutputPaths(outPath)
	dstMinimized := buildMinimizedOutputPaths(destMain)
	for key, srcPath := range srcMinimized {
		if err := copyFileIfExists(srcPath, dstMinimized[key]); err != nil {
			return err
		}
	}

	if strings.HasSuffix(outPath, ".csv") {
		srcRequiredCaps := strings.TrimSuffix(outPath, ".csv") + ".required_caps.csv"
		dstRequiredCaps := strings.TrimSuffix(destMain, ".csv") + ".required_caps.csv"
		if err := copyFileIfExists(srcRequiredCaps, dstRequiredCaps); err != nil {
			return err
		}

		srcPerf := strings.TrimSuffix(outPath, ".csv") + ".perf.csv"
		dstPerf := strings.TrimSuffix(destMain, ".csv") + ".perf.csv"
		if err := copyFileIfExists(srcPerf, dstPerf); err != nil {
			return err
		}

		// NOTE: methods_deviation and accuracy artifacts are temporarily disabled.
		// srcDeviation := strings.TrimSuffix(outPath, ".csv") + ".methods_deviation.csv"
		// dstDeviation := strings.TrimSuffix(destMain, ".csv") + ".methods_deviation.csv"
		// if err := copyFileIfExists(srcDeviation, dstDeviation); err != nil {
		// 	return err
		// }

		// srcAccuracy := strings.TrimSuffix(outPath, ".csv") + ".accuracy.csv"
		// dstAccuracy := strings.TrimSuffix(destMain, ".csv") + ".accuracy.csv"
		// if err := copyFileIfExists(srcAccuracy, dstAccuracy); err != nil {
		// 	return err
		// }
	}

	return copyFileIfExists(outPath+".done", destMain+".done")
}

func ensureExecutionBucketDirs(absOutputRoot, entrypointsAnchor string, csvFiles []string) error {
	if len(csvFiles) == 0 {
		return nil
	}

	dirs := make(map[string]struct{}, 4)
	for _, path := range csvFiles {
		rel, relErr := filepath.Rel(entrypointsAnchor, path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(relSlash, "OSS/") {
			dirs[filepath.Join(absOutputRoot, "OSS", "good_execution")] = struct{}{}
			dirs[filepath.Join(absOutputRoot, "OSS", "bad_execution")] = struct{}{}
			continue
		}
		dirs[filepath.Join(absOutputRoot, "good_execution")] = struct{}{}
		dirs[filepath.Join(absOutputRoot, "bad_execution")] = struct{}{}
	}

	for dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func copyFileIfExists(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.IsDir() {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}

/*
Dead code (unused): superseded by PrepareKernelState.
Kept commented for temporary reference during migration.

func DoResolveGlobalConstants(manager *analysis.AnalysisManager, kernelCapRulesPath string) error {
	if kernelCapRulesPath == "" {
		return fmt.Errorf("kernel capability rules path is empty")
	}

	kb, err := mapping.LoadKernelCapabilityKnowledgeBase(kernelCapRulesPath, mapping.DefaultKernelCapabilityRuleLoadOptions())
	if err != nil {
		return fmt.Errorf("load kernel capability knowledge base: %w", err)
	}

	// NOTE: Global constant resolution cannot happen here because SSA program
	// is not yet built. Constants will be resolved during entrypoint processing
	// and cached in manager.resolvedConstants for reuse.

	fmt.Printf("[INFO] Global constant resolution prepared for %d rules\n", len(kb.Rules))
	return nil
}
*/
/*
Dead code (unused): replaced by PrepareKernelState and manager seeding in
ProcessEntrypointsFile.

func DoLoadKernelCapabilityKnowledgeBase(manager *analysis.AnalysisManager, filePath string) error {
	kb, err := mapping.LoadKernelCapabilityKnowledgeBase(filePath, mapping.DefaultKernelCapabilityRuleLoadOptions())
	if err != nil {
		return err
	}
	manager.SetKernelDemandSinksBySyscall(buildKernelDemandSinksBySyscall(kb))
	return nil
}
*/

/*
Dead code (unused): this legacy single-entry wrapper was replaced by the
PrepareKernelState + ProcessEntrypointWithAnalysisSteps flow.

func DoAnalyzeConditionalCapabilitiesWithKB(manager *analysis.AnalysisManager, filePath string, resolvedConstantsCache map[string]uint64) error {
	kb, err := mapping.LoadKernelCapabilityKnowledgeBase(filePath, mapping.DefaultKernelCapabilityRuleLoadOptions())
	if err != nil {
		return fmt.Errorf("load kernel capability knowledge base: %w", err)
	}
	manager.SetKernelDemandSinksBySyscall(buildKernelDemandSinksBySyscall(kb))

	// Initialize manager's resolved constants with global cache
	if resolvedConstantsCache != nil && len(resolvedConstantsCache) > 0 {
		manager.SetResolvedConstants(resolvedConstantsCache)
	}

	if err := mapping.AnalyzeConditionalCapabilitiesWithKB(manager, kb, manager); err != nil {
		return fmt.Errorf("analyze conditional capabilities: %w", err)
	}

	return nil
}
*/
