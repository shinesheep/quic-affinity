#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_RESTART_TEST PATH_TO_BPF_OBJECT" >&2
  exit 2
fi

qaffd_bin=$1
test_bin=$2
bpf_obj=$3
id=$$
pin_root=/sys/fs/bpf/quic-affinity-test-$id
state_path=/tmp/qaffd-restart-$id.state
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

cleanup() {
  rm -f "$state_path"
  rm -f "$pin_root/qaff_cids" "$pin_root/qaff_workers" \
    "$pin_root/qaff_worker_generations" "$pin_root/qaff_stats" \
    "$pin_root/qaff_config" 2>/dev/null || true
  rmdir "$pin_root" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

if [ ! -d /sys/fs/bpf ]; then
  echo "skipping: /sys/fs/bpf is not available" >&2
  exit 77
fi

mkdir "$pin_root" 2>/dev/null || {
  if command -v sudo >/dev/null 2>&1; then
    sudo -n mkdir "$pin_root" 2>/dev/null || {
      echo "skipping: cannot create bpffs pin root" >&2
      exit 77
    }
    sudo -n chown "$(id -u):$(id -g)" "$pin_root" 2>/dev/null || true
  else
    echo "skipping: cannot create bpffs pin root" >&2
    exit 77
  fi
}

"$test_bin" "$qaffd_bin" "$bpf_obj" "$pin_root" "$state_path"
