// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package render implements a tool for rendering various "visualizations" of Go programs.
// -cgout Given a path for a .dot file, generates the callgraph of the program in that file.
// -ssaout Given a path for a folder, generates subfolders with files containing
// the ssa representation of each package in that file.
package cg

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/loadprogram"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/fake/analysis"
	"github.com/awslabs/ar-go-tools/fake/util"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const usage = `Render callgraphs or ssa representation of your packages.
Usage:
  argot render [options] <package path(s)>
Examples:
Render a callgraph computed using pointer analysis
  % argot render -analysis pointer  -cgout example.dot package...
Print out all the packages in SSA form
  % argot render -ssaout tmpSsa package...
`

// Flags represents the parsed render sub-command flags.
type Flags struct {
	tools.CommonFlags
	cgAnalysis string
}

// NewFlags returns the parsed render sub-command flags from args.
func NewFlags(args []string) (Flags, error) {
	flags := tools.NewUnparsedCommonFlags("cg-builder")
	cgAnalysis := flags.FlagSet.String("analysis", "pointer", "type of call graph analysis to run. One of: pointer, cha, rta, static, vta")
	tools.SetUsage(flags.FlagSet, usage)
	if err := flags.FlagSet.Parse(args); err != nil {
		return Flags{}, fmt.Errorf("failed to parse command render with args %v: %v", args, err)
	}

	return Flags{
		CommonFlags: tools.CommonFlags{
			FlagSet:    flags.FlagSet,
			ConfigPath: *flags.ConfigPath,
			Verbose:    *flags.Verbose,
			WithTest:   *flags.WithTest,
		},
		cgAnalysis: *cgAnalysis,
	}, nil
}

// Run runs the render tool with flags.
//
//gocyclo:ignore
func Run(flags Flags, manager *analysis.AnalysisManager, timeout time.Duration) error {
	// The strings constants are used only here
	var callgraphAnalysisMode lang.CallgraphAnalysisMode
	switch flags.cgAnalysis {
	case "pointer":
		callgraphAnalysisMode = lang.PointerAnalysis
	case "cha":
		callgraphAnalysisMode = lang.ClassHierarchyAnalysis
	case "rta":
		callgraphAnalysisMode = lang.RapidTypeAnalysis
	case "vta":
		callgraphAnalysisMode = lang.VariableTypeAnalysis
	case "static":
		callgraphAnalysisMode = lang.StaticAnalysis
	default:
		return fmt.Errorf("analysis %q not recognized", flags.cgAnalysis)
	}

	var err error
	renderConfig := config.NewDefault() // empty default config
	if flags.ConfigPath != "" {
		config.SetGlobalConfig(flags.ConfigPath)
		renderConfig, err = config.LoadGlobal(nil)
		if err != nil {
			return fmt.Errorf("could not load config %q", flags.ConfigPath)
		}
	}

	loadOptions := config.LoadOptions{
		PackageConfig: nil,
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: true,
	}
	c := config.NewState(renderConfig, "", flags.FlagSet.Args(), loadOptions)
	c.Logger.Infof("Reading sources")
	wps, err := loadprogram.NewState(c).Value()
	if err != nil {
		return fmt.Errorf("could not load program: %v", err)
	}

	// Compute the call graph
	var cg *callgraph.Graph

	fmt.Fprint(os.Stderr, formatutil.Faint("Computing call graph")+"\n")
	start := time.Now()
	cg, err = callgraphAnalysisMode.ComputeCallgraphWithTimeout(wps.Program, timeout)
	cgComputeDuration := time.Since(start).Seconds()
	if err != nil {
		return fmt.Errorf("could not compute callgraph: %v", err)
	}
	fmt.Fprint(os.Stderr, formatutil.Faint(fmt.Sprintf("Computed in %.3f s\n", cgComputeDuration)))

	if cg == nil {
		return fmt.Errorf("no callgraph, check the command arguments")
	}

	allFunctions := ssautil.AllFunctions(wps.Program)
	reachable := lang.CallGraphReachable(cg, false, false)

	util.LogInfo("%d SSA functions", len(allFunctions))
	util.LogInfo("%d entrypoints", countEntrypoints(allFunctions))
	util.LogInfo("%d reachable functions", len(reachable))

	manager.CGBuilderState = wps
	manager.CG = cg

	return nil
}

func countEntrypoints(allFunctions map[*ssa.Function]bool) int {
	entrypoints := 0
	for f := range allFunctions {
		if f == nil || f.Pkg == nil || f.Pkg.Pkg == nil {
			continue
		}
		if f.Pkg.Pkg.Name() != "main" {
			continue
		}
		name := f.Name()
		if name == "main" || strings.HasPrefix(name, "init") {
			entrypoints++
		}
	}
	return entrypoints
}
