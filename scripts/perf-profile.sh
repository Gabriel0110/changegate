#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-profiles}"
mkdir -p "${out_dir}"

go test ./internal/performance \
  -run '^$' \
  -bench 'Benchmark(SmallScan|LargeScan|GraphBuild|OutputRender|CloudContextEnrichment|CloudContextCacheLoad)$' \
  -benchmem \
  -cpuprofile "${out_dir}/cpu.pprof" \
  -memprofile "${out_dir}/mem.pprof"

echo "CPU profile: ${out_dir}/cpu.pprof"
echo "Memory profile: ${out_dir}/mem.pprof"
