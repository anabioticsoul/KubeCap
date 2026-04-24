package analysis

import (
	"fmt"
	"os"

	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/fake/util"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

type KernelDemandSink struct {
	Syscall        string
	Capability     string
	ArgIndices     []int
	ArgCondition   string
	ExtraCondition string
}

type ConditionalCapability struct {
	Capability     string
	ArgCondition   string
	ExtraCondition string
}

type AnalysisManager struct {
	CGBuilderState         *loadprogram.State
	ReachabilityState      *loadprogram.State
	CG                     *callgraph.Graph
	reachableFunctions     []*ssa.Function
	reachableSyscalls      *util.SyscallCategories
	defaultCaps            map[string]struct{}
	sysToCap               map[string][]string
	capToSys               map[string][]string
	kubePMRequiredCaps     []string
	DecapRequiredCaps      []string
	llmDecapRequiredCaps   []string
	licaSysToCaps          map[string][]string // Lica paper: syscall → capability mapping
	licaRequiredCaps       []string            // Lica paper: required capabilities for analyzed entrypoint
	llmLicaRequiredCaps    []string
	conditionalSysToCaps   map[string][]ConditionalCapability // key: syscall, value: conditional capability entries with condition details
	unconditionalSysToCaps map[string][]string                // key: syscall, value: list of capabilities that can be required by the syscall without any condition
	kernelDemandSinks      map[string][]KernelDemandSink
	calculatedCaps         map[string][]ConditionalCapability // set of conditional capabilities calculated to be required for the analyzed entrypoint
	singleEntrySysToCaps   map[string][]string                // complete mapping of syscalls to capabilities, including both conditional and unconditional rules, used for final capability calculation
	allSysToCaps           map[string][]string                // complete mapping of syscalls to capabilities, including both conditional and unconditional rules, used for final capability calculation; this is the union of singleEntrySysToCaps
	resolvedConstants      map[string]uint64                  // global constant resolution cache: constantName → value
	KB                     interface{}                        // *mapping.KernelCapabilityKnowledgeBase, stored as interface{} to avoid import cycle
}

func (this *AnalysisManager) Init() {
	this.CG = nil
	this.reachableFunctions = nil
	this.reachableSyscalls = &util.SyscallCategories{}
	this.defaultCaps = make(map[string]struct{})
	this.sysToCap = make(map[string][]string)
	this.capToSys = make(map[string][]string)
	this.kubePMRequiredCaps = make([]string, 0)
	this.DecapRequiredCaps = make([]string, 0)
	this.llmDecapRequiredCaps = make([]string, 0)
	this.licaRequiredCaps = make([]string, 0)
	this.llmLicaRequiredCaps = make([]string, 0)
	this.licaSysToCaps = make(map[string][]string)
	this.conditionalSysToCaps = make(map[string][]ConditionalCapability)
	this.unconditionalSysToCaps = make(map[string][]string)
	this.kernelDemandSinks = make(map[string][]KernelDemandSink)
	this.calculatedCaps = make(map[string][]ConditionalCapability)
	this.singleEntrySysToCaps = make(map[string][]string)
	this.allSysToCaps = make(map[string][]string)
	this.resolvedConstants = make(map[string]uint64)
}

func (this *AnalysisManager) GetCG() (cg *callgraph.Graph) {
	return this.CG
}

func (this *AnalysisManager) GetReachableFunctions() (functions []*ssa.Function) {
	return this.reachableFunctions
}

// SetReachableFunctions sets the reachable functions in the AnalysisManager.
func (this *AnalysisManager) SetReachableFunctions(functions []*ssa.Function) {
	this.reachableFunctions = functions
}

func (this *AnalysisManager) GetReachableSyscalls() (syscalls *util.SyscallCategories) {
	return this.reachableSyscalls
}

// SetReachableSyscalls sets the reachable syscalls in the AnalysisManager.
func (this *AnalysisManager) SetReachableSyscalls(syscalls *util.SyscallCategories) {
	this.reachableSyscalls = syscalls
}

func (this *AnalysisManager) PrintCG() error {
	if this.CG != nil {
		for function := range this.CG.Nodes {
			if function == nil {
				continue
			}
			fmt.Println(function.Name())
		}
		return nil
	} else {
		return fmt.Errorf("call graph is nil")
	}
}

func (this *AnalysisManager) GetConditionalSysToCaps() map[string][]ConditionalCapability {
	return this.conditionalSysToCaps
}

func (this *AnalysisManager) GetUnconditionalSysToCaps() map[string][]string {
	return this.unconditionalSysToCaps
}

func (this *AnalysisManager) SetDefaultCaps(defaultCaps map[string]struct{}) {
	if defaultCaps == nil {
		this.defaultCaps = make(map[string]struct{})
		return
	}
	this.defaultCaps = defaultCaps
}

func (this *AnalysisManager) GetDefaultCaps() map[string]struct{} {
	return this.defaultCaps
}

func (this *AnalysisManager) SetSysToCap(sysToCap map[string][]string) {
	if sysToCap == nil {
		this.sysToCap = make(map[string][]string)
		return
	}
	this.sysToCap = sysToCap
}

func (this *AnalysisManager) GetSysToCap() map[string][]string {
	return this.sysToCap
}

func (this *AnalysisManager) SetCapToSys(capToSys map[string][]string) {
	if capToSys == nil {
		this.capToSys = make(map[string][]string)
		return
	}
	this.capToSys = capToSys
}

func (this *AnalysisManager) GetCapToSys() map[string][]string {
	return this.capToSys
}

/*
Dead code (unused): the unconditional capability getter was only needed by the
legacy all-in-one conditional capability path.

func (this *AnalysisManager) GetUnconditionalSysToCaps() map[string][]string {
	return this.unconditionalSysToCaps
}
*/

func (this *AnalysisManager) SetUnconditionalSysToCaps(caps map[string][]string) {
	if caps == nil {
		this.unconditionalSysToCaps = make(map[string][]string)
		return
	}
	this.unconditionalSysToCaps = caps
}

// SetConditionalSysToCaps deep-copies the provided map into the manager.
// Each manager gets its own copy so per-entrypoint SSA handlers can append
// without interfering with other entrypoints.
func (this *AnalysisManager) SetConditionalSysToCaps(caps map[string][]ConditionalCapability) {
	this.conditionalSysToCaps = make(map[string][]ConditionalCapability, len(caps))
	for k, v := range caps {
		cp := make([]ConditionalCapability, len(v))
		copy(cp, v)
		this.conditionalSysToCaps[k] = cp
	}
}

func (this *AnalysisManager) GetDecapRequiredCaps() []string {
	return this.DecapRequiredCaps
}

func (this *AnalysisManager) GetKubePMRequiredCaps() []string {
	return this.kubePMRequiredCaps
}

func (this *AnalysisManager) SetKubePMRequiredCaps(kubePMRequiredCaps []string) {
	this.kubePMRequiredCaps = kubePMRequiredCaps
}

func (this *AnalysisManager) SetDecapRequiredCaps(decapRequiredCaps []string) {
	this.DecapRequiredCaps = decapRequiredCaps
}

func (this *AnalysisManager) GetLLMDecapRequiredCaps() []string {
	return this.llmDecapRequiredCaps
}

func (this *AnalysisManager) SetLLMDecapRequiredCaps(llmDecapRequiredCaps []string) {
	this.llmDecapRequiredCaps = llmDecapRequiredCaps
}

func (this *AnalysisManager) GetLicaSysToCaps() map[string][]string {
	if this.licaSysToCaps == nil {
		this.licaSysToCaps = make(map[string][]string)
	}
	return this.licaSysToCaps
}

func (this *AnalysisManager) SetLicaSysToCaps(licaSysToCaps map[string][]string) {
	if licaSysToCaps == nil {
		this.licaSysToCaps = make(map[string][]string)
		return
	}
	this.licaSysToCaps = licaSysToCaps
}

func (this *AnalysisManager) GetLicaRequiredCaps() []string {
	return this.licaRequiredCaps
}

func (this *AnalysisManager) SetLicaRequiredCaps(licaRequiredCaps []string) {
	this.licaRequiredCaps = licaRequiredCaps
}

func (this *AnalysisManager) GetLLMLicaRequiredCaps() []string {
	return this.llmLicaRequiredCaps
}

func (this *AnalysisManager) SetLLMLicaRequiredCaps(llmLicaRequiredCaps []string) {
	this.llmLicaRequiredCaps = llmLicaRequiredCaps
}

func (this *AnalysisManager) GetCalculatedCaps() map[string][]ConditionalCapability {
	return this.calculatedCaps
}

func (this *AnalysisManager) SetCalculatedCaps(calculatedCaps map[string][]ConditionalCapability) {
	if calculatedCaps == nil {
		this.calculatedCaps = make(map[string][]ConditionalCapability)
		return
	}
	this.calculatedCaps = calculatedCaps
}

func (this *AnalysisManager) GetSingleEntrySysToCaps() map[string][]string {
	if this.singleEntrySysToCaps == nil {
		this.singleEntrySysToCaps = make(map[string][]string)
	}
	return this.singleEntrySysToCaps
}

func (this *AnalysisManager) SetSingleEntrySysToCaps(sysToCaps map[string][]string) {
	if sysToCaps == nil {
		this.singleEntrySysToCaps = make(map[string][]string)
		return
	}
	this.singleEntrySysToCaps = sysToCaps
}

func (this *AnalysisManager) GetAllSysToCaps() map[string][]string {
	if this.allSysToCaps == nil {
		this.allSysToCaps = make(map[string][]string)
	}
	return this.allSysToCaps
}

func (this *AnalysisManager) SetAllSysToCaps(sysToCaps map[string][]string) {
	if sysToCaps == nil {
		this.allSysToCaps = make(map[string][]string)
		return
	}
	this.allSysToCaps = sysToCaps
}

func (this *AnalysisManager) SetKB(kb interface{}) {
	this.KB = kb
}

func (this *AnalysisManager) GetKB() interface{} {
	return this.KB
}

func (this *AnalysisManager) SetKernelDemandSinksBySyscall(sinks map[string][]KernelDemandSink) {
	if sinks == nil {
		this.kernelDemandSinks = make(map[string][]KernelDemandSink)
		return
	}
	this.kernelDemandSinks = sinks
}

func (this *AnalysisManager) GetDemandSinksBySyscall(syscall string) []KernelDemandSink {
	if this.kernelDemandSinks == nil || syscall == "" {
		return nil
	}
	result := this.kernelDemandSinks[syscall]
	if len(result) == 0 {
		return nil
	}
	out := make([]KernelDemandSink, len(result))
	copy(out, result)
	return out
}

// SetResolvedConstant stores a resolved constant value globally
func (this *AnalysisManager) SetResolvedConstant(constantName string, value uint64) {
	if this.resolvedConstants == nil {
		this.resolvedConstants = make(map[string]uint64)
	}
	this.resolvedConstants[constantName] = value
}

// GetResolvedConstant retrieves a previously resolved constant value
func (this *AnalysisManager) GetResolvedConstant(constantName string) (uint64, bool) {
	if this.resolvedConstants == nil {
		return 0, false
	}
	val, ok := this.resolvedConstants[constantName]
	return val, ok
}

// SetResolvedConstants sets the entire resolved constants map
func (this *AnalysisManager) SetResolvedConstants(constants map[string]uint64) {
	if constants == nil {
		this.resolvedConstants = make(map[string]uint64)
		return
	}
	this.resolvedConstants = constants
}

// GetResolvedConstants returns the entire resolved constants map
func (this *AnalysisManager) GetResolvedConstants() map[string]uint64 {
	return this.resolvedConstants
}

func ErrExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	hint := tools.HintForErrorMessage(err.Error())
	if hint != "" {
		fmt.Fprintf(os.Stderr, "Hint: %s\n", hint)
	}
	os.Exit(2)
}
