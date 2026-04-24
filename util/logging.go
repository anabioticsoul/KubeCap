package util

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func LogInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func LogWarn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...)
}

func LogError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func LogDebug(enabled bool, format string, args ...interface{}) {
	if !enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
}

func LogVerbose(enabled bool, format string, args ...interface{}) {
	if !enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
}

func LogStageInput(enabled bool, stage string, fields map[string]interface{}) {
	if !enabled {
		return
	}
	LogVerbose(true, "%s input: %s", stage, formatFields(fields))
}

func LogStageOutput(enabled bool, stage string, fields map[string]interface{}) {
	if !enabled {
		return
	}
	LogVerbose(true, "%s output: %s", stage, formatFields(fields))
}

func LogProjectHeader(enabled bool, projectName string) {
	if !enabled {
		return
	}
	LogVerbose(true, "------------------------------------------------------")
	LogVerbose(true, "项目名：%s", projectName)
}

func LogProjectFooter(enabled bool) {
	if !enabled {
		return
	}
	LogVerbose(true, "------------------------------------------------------")
}

func LogStepIO(enabled bool, step string, input map[string]interface{}, output map[string]interface{}) {
	if !enabled {
		return
	}
	LogVerbose(true, "%s，输入：%s，输出：%s", step, formatFields(input), formatFields(output))
}

func formatFields(fields map[string]interface{}) string {
	if len(fields) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	return strings.Join(parts, " ")
}
