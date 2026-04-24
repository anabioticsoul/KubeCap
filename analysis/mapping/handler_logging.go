package mapping

import (
	"fmt"

	"github.com/awslabs/ar-go-tools/fake/util"
	"golang.org/x/tools/go/ssa"
)

var specialHandlerVerbose bool

func SetSpecialHandlerVerbose(enabled bool) {
	specialHandlerVerbose = enabled
}

func logSpecialHandlerFunction(index int, fun *ssa.Function) {
	if fun == nil {
		return
	}
	util.LogVerbose(specialHandlerVerbose, "special handler function: index=%d name=%s", index, fun.Name())
}

func logSpecialHandlerMatch(message string, caller *ssa.Function) {
	if caller == nil {
		return
	}
	util.LogVerbose(specialHandlerVerbose, "%s %s", message, caller.String())
}

func logSpecialHandlerLine(args ...interface{}) {
	util.LogVerbose(specialHandlerVerbose, "%s", fmt.Sprint(args...))
}

func logMappingVerbose(format string, args ...interface{}) {
	util.LogVerbose(specialHandlerVerbose, format, args...)
}

func logMappingDebug(format string, args ...interface{}) {
	util.LogDebug(specialHandlerVerbose, format, args...)
}

func logMappingWarn(format string, args ...interface{}) {
	util.LogWarn(format, args...)
}
