#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 PATH_TO_TEST PATH_TO_BPF_OBJECT" >&2
  exit 2
fi

test_bin=$1
bpf_obj=$2
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

if command -v getcap >/dev/null 2>&1; then
  current_caps=$(getcap "$test_bin" 2>/dev/null || true)
else
  current_caps=
fi

case "$current_caps" in
  *cap_bpf*)
    ;;
  *)
    if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
      sudo -n setcap "$caps" "$test_bin" 2>/dev/null || true
    fi
    ;;
esac

exec "$test_bin" "$bpf_obj"
