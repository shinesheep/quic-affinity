#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_TEST_QAFFD_CONTROL PATH_TO_BPF_OBJECT" >&2
  exit 2
fi

qaffd_bin=$1
test_bin=$2
bpf_obj=$3
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

exec "$test_bin" "$qaffd_bin" "$bpf_obj"

