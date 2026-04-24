package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/awslabs/ar-go-tools/fake/analysis"
	fakeconfig "github.com/awslabs/ar-go-tools/fake/config"
	"github.com/awslabs/ar-go-tools/fake/service"
	"github.com/awslabs/ar-go-tools/fake/util"
)

const defaultSyscallTableURL = "https://android.googlesource.com/kernel/common/+/df2c1f38939aa/arch/x86/entry/syscalls/syscall_64.tbl?format=TEXT"

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func main() {
	// Parse command-line arguments
	entrypointsRoot := flag.String("entrypoints-root", "./input/entrypoints", "root dir containing entrypoints CSV files")
	outputRoot := flag.String("output-root", "./output/results", "root dir to write output CSV files")
	capMappingPath := flag.String("cap2syscall", "./input/Decap/cap2syscall.csv", "capability-to-syscall mapping CSV (Decap paper)")
	licaMappingPath := flag.String("lica-mapping", "./input/Lica/syscall2cap.csv", "syscall-to-capability mapping CSV (Lica paper)")
	groundTruthCaps := flag.String("ground-truth-caps", "./output/test_oracles/oracle.csv", "known true required capabilities CSV: entrypoint,cap1;cap2")
	kernelCapRulesPath := flag.String("kernel-cap-rules", "./input/kernel_cap_rules_5.4.csv", "kernel capability rules CSV")
	defaultCapsPath := flag.String("default-caps", "./input/default_caps.csv", "default capabilities file")
	verbose := flag.Bool("verbose", false, "print detailed analysis progress")
	warnOnFailure := flag.Bool("warn-on-failure", false, "print warnings when analysis fails")
	useKernelRules := flag.Bool("use-kernel-rules", false, "use kernel capability rules for parameter analysis")
	enableComparisons := flag.Bool("enable-comparisons", true, "enable KubePM/Decap/Lica deviation analysis")
	enableAccuracyEval := flag.Bool("enable-accuracy-eval", true, "enable evaluation against ground-truth capability sets")
	enableDecap := flag.Bool("enable-decap", true, "enable Decap required/can-drop results")
	enableLica := flag.Bool("enable-lica", true, "enable Lica required/can-drop results")
	enableLLMDecap := flag.Bool("enable-llm-decap", false, "enable LLMDecap required results")
	enableLLMLica := flag.Bool("enable-llm-lica", false, "enable LLMLica required results")
	reachabilityTool := flag.String("analysis-tool", "reachability", "analysis tool: reachability, dependencies, or render")
	renderAnalysis := flag.String("render-analysis", "pointer", "render analysis kind: pointer, cha, rta, or vta")
	loaderNoInit := flag.Bool("loader-noinit", true, "pass -noinit to reachability loader")
	loaderSuppressErrors := flag.Bool("loader-suppress-load-errors", false, "pass -suppress-load-errors to reachability loader")
	loaderQuiet := flag.Bool("loader-quiet-loader", true, "pass -quiet-loader to reachability loader")
	dumpSyscalls := flag.Bool("dump-syscalls", false, "refresh syscall table from upstream before processing")
	resumeCompleted := flag.Bool("resume-completed", true, "skip projects already completed in previous runs")
	strictEntrypoint := flag.Bool("strict-entrypoint", false, "analyze only CSV entrypoint when it is executable main; otherwise mark invalid_entrypoint")
	saveConsoleLog := flag.Bool("save-console-log", true, "save console stdout/stderr to output/run.log")
	enablePerfMetrics := flag.Bool("enable-perf-metrics", false, "print per-entrypoint time/memory overhead to console")
	entrypointTimeout := flag.Duration("entrypoint-timeout", 0, "per-entrypoint analysis timeout (e.g. 5m); 0 disables timeout")
	flag.Parse()

	if err := run(
		*entrypointsRoot,
		*outputRoot,
		*defaultCapsPath,
		*capMappingPath,
		*licaMappingPath,
		*groundTruthCaps,
		*kernelCapRulesPath,
		*reachabilityTool,
		*verbose,
		*warnOnFailure,
		*useKernelRules,
		*enableComparisons,
		*enableAccuracyEval,
		*enableDecap,
		*enableLica,
		*enableLLMDecap,
		*enableLLMLica,
		*loaderNoInit,
		*loaderSuppressErrors,
		*loaderQuiet,
		*renderAnalysis,
		*dumpSyscalls,
		*resumeCompleted,
		*strictEntrypoint,
		*saveConsoleLog,
		*enablePerfMetrics,
		*entrypointTimeout,
	); err != nil {
		fatal(err)
	}
	util.LogInfo("Analysis completed！")
}

func run(
	entrypointsRoot,
	outputRoot,
	defaultCapsPath,
	capMappingPath,
	licaMappingPath,
	groundTruthCaps,
	kernelCapRulesPath,
	reachabilityTool string,
	verbose,
	warnOnFailure,
	useKernelRules,
	enableComparisons,
	enableAccuracyEval,
	enableDecap,
	enableLica,
	enableLLMDecap,
	enableLLMLica,
	loaderNoInit,
	loaderSuppressErrors,
	loaderQuiet bool,
	renderAnalysis string,
	dumpSyscalls,
	resumeCompleted,
	strictEntrypoint,
	saveConsoleLog,
	enablePerfMetrics bool,
	entrypointTimeout time.Duration,
) error {
	var err error

	if saveConsoleLog {
		cleanupLog, logPath, setupErr := setupConsoleTee(outputRoot)
		if setupErr != nil {
			return fmt.Errorf("setup console log: %w", setupErr)
		}
		defer cleanupLog()
		util.LogInfo("console log file: %s", logPath)
	}

	// Step 2: Optionally refresh syscall table from upstream
	if dumpSyscalls {
		if verbose {
			util.LogInfo("Refreshing syscall table from %s", defaultSyscallTableURL)
		}
		if err := service.DoDumpSyscallFile(false, defaultSyscallTableURL, "./input/unix_syscalls.csv", "./input/extracted_syscalls.csv"); err != nil {
			if !warnOnFailure {
				return fmt.Errorf("dump syscall: %w", err)
			}
			util.LogWarn("Failed to dump syscall: %v", err)
		}
	}

	// Build config object for batch processing
	config := &fakeconfig.ExportConfig{
		DefaultCapsPath:    defaultCapsPath,
		CapMappingPath:     capMappingPath,
		LicaMappingPath:    licaMappingPath,
		GroundTruthCapsCSV: groundTruthCaps,
		KernelCapRulesPath: kernelCapRulesPath,
		SyscallTableURL:    defaultSyscallTableURL,
		SyscallUnixPath:    "./input/unix_syscalls.csv",
		SyscallExtractPath: "./input/extracted_syscalls.csv",
		Verbose:            verbose,
		WarnOnFailure:      warnOnFailure,
		ResumeCompleted:    resumeCompleted,
		StrictEntrypoint:   strictEntrypoint,
		UseKernelRules:     useKernelRules,
		EnableComparisons:  enableComparisons,
		EnableAccuracyEval: enableAccuracyEval,
		EnableDecap:        enableDecap,
		EnableLica:         enableLica,
		EnableLLMDecap:     enableLLMDecap,
		EnableLLMLica:      enableLLMLica,
		ReachabilityTool:   reachabilityTool,
		RenderAnalysis:     renderAnalysis,
		LoaderNoInit:       loaderNoInit,
		LoaderSuppressErrs: loaderSuppressErrors,
		LoaderQuiet:        loaderQuiet,
		DumpSyscallTable:   false, // Already done above if needed
		EnablePerfMetrics:  enablePerfMetrics,
		EntrypointTimeout:  entrypointTimeout,
	}
	util.LogStageInput(verbose, "Global", map[string]interface{}{
		"entrypoints_root":   entrypointsRoot,
		"output_root":        outputRoot,
		"cap_mapping":        capMappingPath,
		"lica_mapping":       licaMappingPath,
		"ground_truth":       groundTruthCaps,
		"default_caps":       defaultCapsPath,
		"kernel_rules":       kernelCapRulesPath,
		"use_kernel_rules":   useKernelRules,
		"comparisons":        enableComparisons,
		"accuracy_eval":      enableAccuracyEval,
		"enable_decap":       enableDecap,
		"enable_lica":        enableLica,
		"enable_llm_decap":   enableLLMDecap,
		"enable_llm_lica":    enableLLMLica,
		"analysis_tool":      reachabilityTool,
		"render_analysis":    renderAnalysis,
		"loader_noinit":      loaderNoInit,
		"loader_suppress":    loaderSuppressErrors,
		"loader_quiet":       loaderQuiet,
		"warn_on_failure":    warnOnFailure,
		"strict_entrypoint":  strictEntrypoint,
		"enable_perf":        enablePerfMetrics,
		"entrypoint_timeout": entrypointTimeout,
	})

	if verbose {
		util.LogInfo("Loading runtime mappings from %s, %s, and %s", defaultCapsPath, capMappingPath, licaMappingPath)
	}

	// Step 3: Perform Stage-1 global constant resolution via string search (before processing any entrypoints)
	// This phase quickly identifies constants by scanning source code for const definitions
	resolvedConstants := make(map[string]uint64)
	if useKernelRules && kernelCapRulesPath != "" {
		if verbose {
			util.LogInfo("Stage 1: Global constant search by string matching")
			util.LogStageInput(verbose, "Stage 1", map[string]interface{}{"search_dirs": []string{".", "./target"}})
		}
		// Search in both project root and target projects (where vendor dependencies are)
		searchDirs := []string{".", "./target"}
		resolvedConstants = service.DoGlobalConstantSearchByString(searchDirs, verbose)
		if verbose {
			util.LogInfo("Stage 1 found %d constants from string search", len(resolvedConstants))
			util.LogStageOutput(verbose, "Stage 1", map[string]interface{}{"resolved_constants": len(resolvedConstants)})
		}
	}

	// Stage A: Preload and classify kernel capability rules once (after Step 3).
	var baseManager *analysis.AnalysisManager
	baseManager, err = service.PrepareKernelState(config)
	if err != nil {
		return fmt.Errorf("prepare kernel state: %w", err)
	}
	if baseManager == nil {
		baseManager = new(analysis.AnalysisManager)
		baseManager.Init()
	}
	util.LogStageOutput(verbose, "Stage A", map[string]interface{}{
		"has_base_manager":     baseManager != nil,
		"has_kb":               baseManager.GetKB() != nil,
		"conditional_syscalls": len(baseManager.GetConditionalSysToCaps()),
	})

	if enableDecap || enableLLMDecap {
		if err := service.DoLoadMappingFromFile(baseManager, capMappingPath); err != nil {
			return fmt.Errorf("load cap mapping: %w", err)
		}
	}

	if enableLica || enableLLMLica {
		if err := service.DoLoadLicaMappingFromFile(baseManager, licaMappingPath); err != nil {
			return fmt.Errorf("load lica mapping: %w", err)
		}
	}

	util.LogStageOutput(verbose, "[KubePM] Mapping", map[string]interface{}{
		"sys_to_cap": len(baseManager.GetConditionalSysToCaps()) + len(baseManager.GetUnconditionalSysToCaps()),
	})

	util.LogStageOutput(verbose, "[Decap] Mapping", map[string]interface{}{
		"enabled":        enableDecap,
		"llm_enabled":    enableLLMDecap,
		"mapping_loaded": enableDecap || enableLLMDecap,
		"sys_to_cap":     len(baseManager.GetSysToCap()),
		"cap_to_sys":     len(baseManager.GetCapToSys()),
	})

	util.LogStageOutput(verbose, "[Lica] Mapping", map[string]interface{}{
		"enabled":        enableLica,
		"llm_enabled":    enableLLMLica,
		"mapping_loaded": enableLica || enableLLMLica,
		"sys_to_cap":     len(baseManager.GetLicaSysToCaps()),
	})

	if err := service.DoLoadDefaultCapsFromFile(baseManager, defaultCapsPath); err != nil {
		return fmt.Errorf("load default caps: %w", err)
	}
	util.LogStageOutput(verbose, "DefaultCaps", map[string]interface{}{"default_caps": len(baseManager.GetDefaultCaps())})
	baseManager.SetResolvedConstants(resolvedConstants)
	util.LogStageOutput(verbose, "ConstantCache", map[string]interface{}{"resolved_constants": len(baseManager.GetResolvedConstants())})

	// Step 4: Process all entrypoints
	// Stage 2 constant resolution (SSA-based propagation) happens during entrypoint processing
	// for any constants not found in Stage 1
	if verbose {
		util.LogInfo("Processing entrypoints from %s (Stage 2 will resolve missing constants)", entrypointsRoot)
	}

	stats, err := service.DoExportCanDropCSVs(entrypointsRoot, outputRoot, config, baseManager)
	if err != nil {
		return fmt.Errorf("export can-drop: %w", err)
	}

	// Step 5: Print statistics
	if verbose {
		util.LogInfo(
			"[STATS] total=%d failed=%d empty=%d with-data=%d without-data=%d",
			stats.TotalEntrypoints,
			stats.FailedEntrypoints,
			stats.EmptyFiles,
			stats.SuccessWithData,
			stats.SuccessWithoutData,
		)
	}

	return nil
}

func fatal(err error) {
	util.LogError("%v", err)
	os.Exit(1)
}

func setupConsoleTee(outputRoot string) (func(), string, error) {
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return nil, "", err
	}

	logPath := filepath.Join(outputRoot, "run.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, "", err
	}
	if _, err := fmt.Fprintf(logFile, "\n===== run start %s =====\n", time.Now().Format(time.RFC3339)); err != nil {
		_ = logFile.Close()
		return nil, "", err
	}

	origStdout := os.Stdout
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		_ = logFile.Close()
		return nil, "", err
	}

	os.Stdout = w
	os.Stderr = w

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.MultiWriter(origStdout, &ansiStrippingWriter{w: logFile}), r)
		close(done)
	}()

	cleanup := func() {
		_ = w.Close()
		<-done
		os.Stdout = origStdout
		os.Stderr = origStderr
		_ = r.Close()
		_ = logFile.Close()
	}

	return cleanup, logPath, nil
}

type ansiStrippingWriter struct {
	w io.Writer
}

func (w *ansiStrippingWriter) Write(p []byte) (int, error) {
	cleaned := ansiEscapePattern.ReplaceAll(p, nil)
	if _, err := w.w.Write(cleaned); err != nil {
		return 0, err
	}
	return len(p), nil
}
