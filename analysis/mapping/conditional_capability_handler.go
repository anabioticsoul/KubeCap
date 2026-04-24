package mapping

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/awslabs/ar-go-tools/fake/analysis"
	"golang.org/x/tools/go/ssa"
)

type SyscallCapabilityContextWithAnalyzer interface {
	GetReachableFunctions() []*ssa.Function
	GetCalculatedCaps() map[string][]analysis.ConditionalCapability
}

// ClassifyKBRules classifies KB rules into conditional and unconditional maps.
// This is a one-time global operation; it does not require SSA analysis.
// Call it once before processing any entrypoints, then seed each AnalysisManager
// via SetConditionalSysToCaps / SetUnconditionalSysToCaps.
func ClassifyKBRules(kb *KernelCapabilityKnowledgeBase) (map[string][]analysis.ConditionalCapability, map[string][]string) {
	conditionalMap := make(map[string][]analysis.ConditionalCapability)
	unconditionalMap := make(map[string][]string)
	loggedRules := make(map[string]struct{})

	for _, rule := range kb.Rules {
		if rule.Syscall == "" {
			continue
		}
		isCond := isConditionalRule(rule)
		for _, cap := range rule.Capability {
			if isCond {
				argCond := rule.ArgCondition
				if argCond == "" {
					argCond = "true"
				}
				extraCond := rule.ExtraCondition
				if extraCond == "" {
					extraCond = "true"
				}
				appendUniqueConditionalCap(conditionalMap, rule.Syscall, cap, argCond, extraCond)
				logKey := rule.Syscall + "|" + cap + "|" + argCond + "|" + extraCond
				if _, ok := loggedRules[logKey]; !ok {
					loggedRules[logKey] = struct{}{}
					//输出 条件规则
					// util.LogInfo("Conditional rule: syscall=%s cap=%s arg_condition=%q extra_condition=%q", rule.Syscall, cap, argCond, extraCond)
				}
			} else {
				appendUniqueCap(unconditionalMap, rule.Syscall, cap)
			}
		}
	}
	return conditionalMap, unconditionalMap
}

// PropagateConstantsWithKB performs per-entrypoint SSA-based constant propagation
// for conditional rules. The manager must already have its conditional map
// pre-seeded via SetConditionalSysToCaps before this is called.
func PropagateConstantsWithKB(ctx SyscallCapabilityContextWithAnalyzer, kb *KernelCapabilityKnowledgeBase, manager *analysis.AnalysisManager) error {
	if kb == nil {
		return fmt.Errorf("kernel capability knowledge base is nil")
	}
	if manager == nil {
		return fmt.Errorf("analysis manager is nil")
	}

	rawFuncs := ctx.GetReachableFunctions()
	funcs := make([]*ssa.Function, 0, len(rawFuncs))
	for _, fn := range rawFuncs {
		if fn != nil {
			funcs = append(funcs, fn)
		}
	}
	conditionalMap := ctx.GetCalculatedCaps()
	if conditionalMap == nil {
		conditionalMap = make(map[string][]analysis.ConditionalCapability)
		manager.SetCalculatedCaps(conditionalMap)
	}
	analyzer := NewConditionalCapabilityAnalyzer(kb)
	globalConstCache := manager.GetResolvedConstants()

	specialHandled := make(map[string]struct{})
	propagatedArgs := make(map[string]struct{})

	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Pos() < funcs[j].Pos()
	})

	for _, rule := range kb.Rules {
		if rule.Syscall == "" || !isConditionalRule(rule) {
			continue
		}

		argIndices := append([]int(nil), rule.ArgIndices...)
		if len(argIndices) == 0 {
			argIndices = analyzer.ExtractArgIndexFromCondition(rule.ArgCondition)
		}

		if _, ok := specialHandled[rule.Syscall]; !ok {
			// These handlers are currently too permissive and can over-approximate
			// CAP_SYS_ADMIN for most Go binaries (e.g., runtime mmap/ptrace/open paths).
			// Prefer condition-driven propagation for these syscalls.
			if rule.Syscall == "open" || rule.Syscall == "mmap" || rule.Syscall == "ptrace" {
				specialHandled[rule.Syscall] = struct{}{}
			} else if RunSpecialHandlerForSyscall(rule.Syscall, funcs, conditionalMap) {
				specialHandled[rule.Syscall] = struct{}{}
				continue
			}
		}

		switch rule.Syscall {
		default:
			for _, argIdx := range argIndices {
				propagateKey := fmt.Sprintf("%s#%d", rule.Syscall, argIdx)
				if _, ok := propagatedArgs[propagateKey]; ok {
					continue
				}
				propagatedArgs[propagateKey] = struct{}{}

				// Check manager's resolved constants cache, _ denotes cachedVal
				cacheKey := rule.Syscall + "_arg" + strconv.Itoa(argIdx)
				if _, found := manager.GetResolvedConstant(cacheKey); found {
					// util.LogInfo("Cache hit: %s arg[%d] = 0x%x", rule.Syscall, argIdx, cachedVal)
					continue
				}

				// propagation variable info
				// util.LogDebug(true, "Propagating for %s arg[%d] with %d funcs and %d cached constants", rule.Syscall, argIdx, len(funcs), len(globalConstCache))

				result, err := analyzer.ConstantPropagation(funcs, rule.Syscall, argIdx, globalConstCache)
				if err != nil || result.IsUnresolved {
					continue
				}
				if result.ResolvedValue != nil {
					manager.SetResolvedConstant(cacheKey, *result.ResolvedValue)
				}
			}
		}
	}
	return nil
}

func isConditionalRule(rule KernelCapabilityRule) bool {
	if rule.ArgCondition != "" && rule.ArgCondition != "true" {
		return true
	}
	if rule.ExtraCondition != "" && rule.ExtraCondition != "true" {
		return true
	}
	return false
}

func appendUniqueCap(target map[string][]string, syscall string, capability string) {
	for _, existing := range target[syscall] {
		if existing == capability {
			return
		}
	}
	target[syscall] = append(target[syscall], capability)
}

func appendUniqueConditionalCap(target map[string][]analysis.ConditionalCapability, syscall string, capability string, argCondition string, extraCondition string) {
	for _, existing := range target[syscall] {
		if existing.Capability == capability && existing.ArgCondition == argCondition && existing.ExtraCondition == extraCondition {
			return
		}
	}
	target[syscall] = append(target[syscall], analysis.ConditionalCapability{
		Capability:     capability,
		ArgCondition:   argCondition,
		ExtraCondition: extraCondition,
	})
}

/*
Dead code (unused): this legacy all-in-one entrypoint was replaced by the
split workflow `ClassifyKBRules + PropagateConstantsWithKB`.

func AnalyzeConditionalCapabilitiesWithKB(ctx SyscallCapabilityContextWithAnalyzer, kb *KernelCapabilityKnowledgeBase, manager *analysis.AnalysisManager) error {
	if kb == nil {
		return fmt.Errorf("kernel capability knowledge base is nil")
	}
	if manager == nil {
		return fmt.Errorf("analysis manager is nil")
	}

	funcs := ctx.GetReachableFunctions()
	conditionalMap := ctx.GetConditionalSysToCaps()
	unconditionalMap := make(map[string][]string)

	analyzer := NewConditionalCapabilityAnalyzer(kb)

	// Set global constant cache from manager (Stage 1 string search results)
	if manager != nil {
		analyzer.SetGlobalConstCache(manager.GetResolvedConstants())
	}

	specialHandled := make(map[string]struct{})
	propagatedArgs := make(map[string]struct{})
	loggedConditionalRules := make(map[string]struct{})

	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Pos() < funcs[j].Pos()
	})

	for _, rule := range kb.Rules {
		if rule.Syscall == "" {
			continue
		}

		isConditional := isConditionalRule(rule)
		for _, cap := range rule.Capability {
			if isConditional {
				argCond := rule.ArgCondition
				if argCond == "" {
					argCond = "true"
				}
				extraCond := rule.ExtraCondition
				if extraCond == "" {
					extraCond = "true"
				}
				appendUniqueConditionalCap(conditionalMap, rule.Syscall, cap, argCond, extraCond)
				logKey := rule.Syscall + "|" + cap + "|" + argCond + "|" + extraCond
				if _, ok := loggedConditionalRules[logKey]; !ok {
					loggedConditionalRules[logKey] = struct{}{}
					util.LogVerbose("[INFO] Conditional rule: syscall=%s cap=%s arg_condition=%q extra_condition=%q\n", rule.Syscall, cap, argCond, extraCond)
				}
			} else {
				appendUniqueCap(unconditionalMap, rule.Syscall, cap)
			}
		}

		if !isConditional {
			continue
		}

		argIndices := append([]int(nil), rule.ArgIndices...)
		if len(argIndices) == 0 {
			argIndices = analyzer.ExtractArgIndexFromCondition(rule.ArgCondition)
		}

		switch rule.Syscall {
		case "fcntl":
			if _, ok := specialHandled[rule.Syscall]; !ok {
				Handler_fcntl(funcs, conditionalMap)
				specialHandled[rule.Syscall] = struct{}{}
			}
		case "ioctl":
			if _, ok := specialHandled[rule.Syscall]; !ok {
				Handler_ioctl(funcs, conditionalMap)
				specialHandled[rule.Syscall] = struct{}{}
			}
		default:
			for _, argIdx := range argIndices {
				propagateKey := fmt.Sprintf("%s#%d", rule.Syscall, argIdx)
				if _, ok := propagatedArgs[propagateKey]; ok {
					continue
				}
				propagatedArgs[propagateKey] = struct{}{}

				// Check manager's resolved constants cache first
				cacheKey := rule.Syscall + "_arg" + strconv.Itoa(argIdx)
				if cachedVal, found := manager.GetResolvedConstant(cacheKey); found {
					util.LogVerbose("[INFO] Cache hit: %s arg[%d] = 0x%x\n", rule.Syscall, argIdx, cachedVal)
					continue
				}

				result, err := analyzer.ConstantPropagation(funcs, rule.Syscall, argIdx)
				if err != nil || result.IsUnresolved {
					if err != nil {
						util.LogVerbose("[WARN] Failed to resolve constant for %s arg[%d]: %v\n", rule.Syscall, argIdx, err)
					} else {
						if result.ConstantName != "" {
							util.LogVerbose("[INFO] Unresolved: %s arg[%d] (%s)\n", rule.Syscall, argIdx, result.ConstantName)
						} else {
							util.LogVerbose("[INFO] Unresolved: %s arg[%d]\n", rule.Syscall, argIdx)
						}
					}
				} else if result.ResolvedValue != nil {
					// Store newly resolved constant in cache
					manager.SetResolvedConstant(cacheKey, *result.ResolvedValue)
					if result.ConstantName != "" {
						util.LogVerbose("[INFO] Resolved %s arg[%d]: %s = 0x%x\n", rule.Syscall, argIdx, result.ConstantName, *result.ResolvedValue)
					} else {
						util.LogVerbose("[INFO] Resolved %s arg[%d] = 0x%x\n", rule.Syscall, argIdx, *result.ResolvedValue)
					}
				}
			}
		}
	}

	ctx.SetUnconditionalSysToCaps(unconditionalMap)
	return nil
}
*/
