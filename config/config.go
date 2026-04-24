package config

import "time"

// ExportStats tracks statistics during batch export.
type ExportStats struct {
	TotalEntrypoints   int
	FailedEntrypoints  int
	EmptyFiles         int
	SuccessWithData    int
	SuccessWithoutData int
}

// ExportConfig holds configuration for batch export operations.
type ExportConfig struct {
	DefaultCapsPath    string
	CapMappingPath     string
	LicaMappingPath    string
	GroundTruthCapsCSV string // Known true required capabilities CSV (entrypoint,caps)
	KernelCapRulesPath string
	SyscallTableURL    string // Android kernel syscall table URL
	SyscallUnixPath    string // Path to unix_syscalls.csv
	SyscallExtractPath string // Path to extracted_syscalls.csv
	Verbose            bool
	WarnOnFailure      bool
	ResumeCompleted    bool // Skip projects that have already finished in a previous run.
	StrictEntrypoint   bool // If true, only analyze CSV entrypoint when it is executable main.
	UseKernelRules     bool
	EnableComparisons  bool   // Enable KubePM/Decap/Lica pairwise deviation analysis
	EnableAccuracyEval bool   // Enable evaluation against known ground-truth capability sets
	EnableDecap        bool   // Enable Decap required/can-drop outputs
	EnableLica         bool   // Enable Lica required/can-drop outputs
	EnableLLMDecap     bool   // Enable LLMDecap required outputs
	EnableLLMLica      bool   // Enable LLMLica required outputs
	ReachabilityTool   string // Analysis tool: reachability, dependencies, or render
	RenderAnalysis     string // Render analysis: pointer, cha, rta, or vta
	LoaderNoInit       bool   // Pass -noinit to reachability loader
	LoaderSuppressErrs bool   // Pass -suppress-load-errors to reachability loader
	LoaderQuiet        bool   // Pass -quiet-loader to reachability loader
	DumpSyscallTable   bool   // Whether to call DoDumpSyscallFile for refreshing syscall lists
	EnablePerfMetrics  bool   // Print per-entrypoint performance metrics to console
	EntrypointTimeout  time.Duration
}
