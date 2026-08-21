#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FUZZER DICTIONARY" >&2
  exit 2
fi

fuzzer=$1
dictionary=$2
run_count=${QAFF_FUZZ_RUNS:-1000}
artifact_dir=/tmp/qaff-fuzz-artifacts-$$
ASAN_OPTIONS=${ASAN_OPTIONS:-halt_on_error=1}
ASAN_OPTIONS=$ASAN_OPTIONS:detect_leaks=${QAFF_FUZZ_DETECT_LEAKS:-0}
export ASAN_OPTIONS

cleanup() {
  status=$?
  if [ "$status" -eq 0 ]; then
    rm -rf "$artifact_dir"
  else
    echo "fuzz artifacts retained at $artifact_dir" >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$artifact_dir"

"$fuzzer" \
  -artifact_prefix="$artifact_dir/" \
  -dict="$dictionary" \
  -max_len=8192 \
  -print_final_stats=1 \
  -timeout=10 \
  -runs="$run_count"
