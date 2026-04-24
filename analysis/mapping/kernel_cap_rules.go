package mapping

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var argRefRegexp = regexp.MustCompile(`arg\[(\d+)\]`)

type KernelCapabilityRule struct {
	Syscall        string
	Capability     []string
	ArgCondition   string
	ExtraCondition string
	ArgIndices     []int
}

type DemandSink struct {
	Syscall        string
	Capability     string
	ArgIndices     []int
	ArgCondition   string
	ExtraCondition string
}

type KernelCapabilityKnowledgeBase struct {
	Rules     []KernelCapabilityRule
	BySyscall map[string][]*KernelCapabilityRule
}

type KernelCapabilityRuleLoadOptions struct {
	SkipWithoutSyscall    bool
	SkipWithoutCapability bool
}

func DefaultKernelCapabilityRuleLoadOptions() KernelCapabilityRuleLoadOptions {
	return KernelCapabilityRuleLoadOptions{
		SkipWithoutSyscall:    true,
		SkipWithoutCapability: true,
	}
}

func LoadKernelCapabilityKnowledgeBase(path string, opts KernelCapabilityRuleLoadOptions) (*KernelCapabilityKnowledgeBase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open kernel capability rule csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true

	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	index := make(map[string]int, len(headers))
	for i, header := range headers {
		index[strings.TrimSpace(header)] = i
	}

	kb := &KernelCapabilityKnowledgeBase{
		BySyscall: make(map[string][]*KernelCapabilityRule),
	}

	for {
		record, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read csv record: %w", readErr)
		}

		rule := parseKernelCapabilityRule(index, record)
		if opts.SkipWithoutSyscall && rule.Syscall == "" {
			continue
		}
		if opts.SkipWithoutCapability && len(rule.Capability) == 0 {
			continue
		}

		rule.ArgIndices = collectArgIndices(rule.ArgCondition, rule.ExtraCondition)

		kb.Rules = append(kb.Rules, rule)
	}

	kb.buildIndexes()

	return kb, nil
}

func (kb *KernelCapabilityKnowledgeBase) buildIndexes() {
	for i := range kb.Rules {
		rule := &kb.Rules[i]
		if rule.Syscall != "" {
			kb.BySyscall[rule.Syscall] = append(kb.BySyscall[rule.Syscall], rule)
		}
	}
}

func (kb *KernelCapabilityKnowledgeBase) GetDemandSinksBySyscall(syscall string) []DemandSink {
	if kb == nil || syscall == "" {
		return nil
	}

	grouped := kb.BySyscall[syscall]
	if len(grouped) == 0 {
		return nil
	}

	return buildDemandSinksFromRules(grouped)
}

func buildDemandSinksFromRules(rules []*KernelCapabilityRule) []DemandSink {
	sinks := make([]DemandSink, 0)
	for _, rule := range rules {
		for _, capName := range rule.Capability {
			sinks = append(sinks, DemandSink{
				Syscall:        rule.Syscall,
				Capability:     capName,
				ArgIndices:     append([]int(nil), rule.ArgIndices...),
				ArgCondition:   rule.ArgCondition,
				ExtraCondition: rule.ExtraCondition,
			})
		}
	}
	return sinks
}

func parseKernelCapabilityRule(index map[string]int, record []string) KernelCapabilityRule {
	return KernelCapabilityRule{
		Syscall:        getCSVString(index, record, "syscall"),
		Capability:     parseCapabilities(getCSVString(index, record, "capability")),
		ArgCondition:   normalizeCondition(getCSVString(index, record, "arg_condition")),
		ExtraCondition: normalizeCondition(getCSVString(index, record, "extra_condition")),
	}
}

func collectArgIndices(conditions ...string) []int {
	indicesSet := make(map[int]struct{})
	for _, condition := range conditions {
		if condition == "" || condition == "true" {
			continue
		}
		matches := argRefRegexp.FindAllStringSubmatch(condition, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			argIdx, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			indicesSet[argIdx] = struct{}{}
		}
	}

	indices := make([]int, 0, len(indicesSet))
	for argIndex := range indicesSet {
		indices = append(indices, argIndex)
	}
	sort.Ints(indices)
	return indices
}

func parseCapabilities(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		c := strings.TrimSpace(part)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}

	sort.Strings(out)
	return out
}

func normalizeCondition(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "true"
	}
	return v
}

func getCSVString(index map[string]int, record []string, column string) string {
	i, ok := index[column]
	if !ok || i < 0 || i >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[i])
}
