#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_QAFFCTL PATH_TO_QUICHE_UDP_SMOKE PATH_TO_BPF_OBJECT CERT KEY" >&2
  exit 2
fi

qaffd_bin=$1
qaffctl_bin=$2
smoke_bin=$3
bpf_obj=$4
cert=$5
key=$6
sock=/tmp/qaff-quiche-passive-egress-$$.sock
out=/tmp/qaff-quiche-passive-egress-$$.out
err=/tmp/qaff-quiche-passive-egress-$$.err
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep
cgroup_path=/sys/fs/cgroup

cleanup() {
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock" "$out" "$err"
}
trap cleanup EXIT INT TERM

if [ "$(stat -fc %T "$cgroup_path" 2>/dev/null || true)" != "cgroup2fs" ]; then
  echo "skipping: cgroup v2 is not available" >&2
  exit 77
fi

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --passive-affinity \
  --egress-cgroup "$cgroup_path" >"$out" 2>"$err" &
daemon_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" config "$sock" >"$out" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$err" >&2 || true
    echo "skipping: qaffd could not attach egress learner" >&2
    exit 77
  fi
  sleep 0.02
done

if [ "$ready" -ne 1 ]; then
  cat "$err" >&2 || true
  echo "skipping: qaffd egress learner did not become ready" >&2
  exit 77
fi

grep -q '^passive_affinity_enabled=1$' "$out"
grep -q '^egress_attached=1$' "$out"

"$smoke_bin" --passive-egress "$sock" "$cert" "$key"

wait "$daemon_pid"
daemon_pid=
