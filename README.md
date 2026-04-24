# KubeCap

KubeCap is a static-analysis framework for capability minimization in Kubernetes workloads. It analyzes workload entrypoints, infers required Linux capabilities from reachable system-call behavior, compares the inferred capability set with capabilities declared in Kubernetes manifests, and reports redundant capabilities that can be safely removed.

KubeCap is designed to support least-privilege hardening of Kubernetes workloads by connecting container entrypoints, static reachability analysis, syscall–capability mappings, and capability deviation analysis.

## Overview

Linux capabilities divide root privileges into fine-grained permissions such as `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and `CAP_NET_RAW`. In Kubernetes, these capabilities can be configured through the container `securityContext`. However, real-world manifests often over-grant capabilities or rely on permissive defaults.

KubeCap helps identify unnecessary capabilities by analyzing which capabilities are actually required by a workload. Given workload entrypoints and capability-mapping rules, KubeCap computes required and removable capabilities, and exports analysis results for further inspection or manifest repair.

## Features

- Entrypoint-level capability analysis for Kubernetes-related workloads.
- Reachability-guided syscall analysis based on Go static analysis.
- Support for multiple analysis strategies, including reachability, dependency analysis, and rendered call-graph analysis.
- Integration with syscall-to-capability mappings, including Decap-style and LiCA-style mappings.
- Optional kernel-rule-based capability analysis.
- Optional evaluation against ground-truth capability sets.
- Batch processing of multiple projects and entrypoints.
- CSV output for required capabilities, removable capabilities, and comparison results.
- Resume mode for skipping previously completed projects.
- Runtime logging and optional performance metrics.

## Repository Structure

```text
KubeCap/
├── analysis/        # Core analysis data structures and analysis manager
├── config/          # Configuration-related definitions
├── eval/            # Evaluation utilities
├── reachability/    # Reachability and call-graph analysis components
├── service/         # Main analysis services and batch-processing logic
├── util/            # Logging and utility functions
├── main.go          # Command-line entry point
└── LICENSE          # MIT License
