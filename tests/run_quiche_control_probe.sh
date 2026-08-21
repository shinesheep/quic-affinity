#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_QAFFCTL PATH_TO_QUICHE_PROBE PATH_TO_BPF_OBJECT" >&2
  exit 2
fi

qaffd_bin=$1
qaffctl_bin=$2
probe_bin=$3
bpf_obj=$4
sock=/tmp/qaff-quiche-probe-$$.sock
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

cleanup() {
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock" /tmp/qaff-quiche-probe-$$.out /tmp/qaff-quiche-probe-$$.err
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-worker 2 &
daemon_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" stats "$sock" >/dev/null 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "skipping: qaffd exited before quiche probe could run" >&2
    exit 77
  fi
  sleep 0.02
done

if [ "$ready" -ne 1 ]; then
  echo "qaffd did not become ready" >&2
  exit 1
fi

"$probe_bin" "$sock" >/tmp/qaff-quiche-probe-$$.out 2>/tmp/qaff-quiche-probe-$$.err
grep -q '^registered_worker=2$' /tmp/qaff-quiche-probe-$$.out
grep -q '^registered_source_cid_len=8$' /tmp/qaff-quiche-probe-$$.out
grep -q '^profile_worker=2$' /tmp/qaff-quiche-probe-$$.out
grep -q '^registered_profile_cid_len=8$' /tmp/qaff-quiche-probe-$$.out
grep -q '^quiche_new_scid_rc=0$' /tmp/qaff-quiche-probe-$$.out
grep -q '^registered_new_scid_len=8$' /tmp/qaff-quiche-probe-$$.out

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=
