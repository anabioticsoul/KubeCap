package mapping

import (
	"github.com/awslabs/ar-go-tools/fake/analysis"
	"golang.org/x/tools/go/ssa"
)

type ConditionalCapabilityContext interface {
	GetReachableFunctions() []*ssa.Function
	GetCalculatedCaps() map[string][]analysis.ConditionalCapability
}

func HandleAllConditionalCaps(manager ConditionalCapabilityContext) {
	funcs := manager.GetReachableFunctions()
	mapping := manager.GetCalculatedCaps()
	if mapping == nil {
		if am, ok := manager.(*analysis.AnalysisManager); ok {
			am.SetCalculatedCaps(make(map[string][]analysis.ConditionalCapability))
			mapping = am.GetCalculatedCaps()
		} else {
			return
		}
	}
	RunAllSpecialHandlers(funcs, mapping)
	return
}
