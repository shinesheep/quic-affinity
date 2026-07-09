#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_QAFFCTL PATH_TO_BPF_OBJECT" >&2
  exit 2
fi

qaffd_bin=$1
qaffctl_bin=$2
bpf_obj=$3
sock=/tmp/qaffctl-control-$$.sock
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

cleanup() {
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock"
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 --fallback-worker 1 &
daemon_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" stats "$sock" >/tmp/qaffctl-control-$$.out 2>/tmp/qaffctl-control-$$.err; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat /tmp/qaffctl-control-$$.err >&2 || true
    echo "skipping: qaffd exited before qaffctl could connect" >&2
    exit 77
  fi
  sleep 0.02
done

if [ "$ready" -ne 1 ]; then
  cat /tmp/qaffctl-control-$$.err >&2 || true
  echo "qaffctl stats did not become ready" >&2
  exit 1
fi

"$qaffctl_bin" health "$sock" >/tmp/qaffctl-control-$$.health
grep -q '^ok=1$' /tmp/qaffctl-control-$$.health
grep -q '^attached=0$' /tmp/qaffctl-control-$$.health
grep -q '^worker_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.health

"$qaffctl_bin" config "$sock" >/tmp/qaffctl-control-$$.config
grep -q '^short_cid_len=8$' /tmp/qaffctl-control-$$.config
grep -q '^attached=0$' /tmp/qaffctl-control-$$.config
grep -q '^worker_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^fallback_worker_id=1$' /tmp/qaffctl-control-$$.config
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.config
grep -q '^pin_root=$' /tmp/qaffctl-control-$$.config
grep -q '^state_path=$' /tmp/qaffctl-control-$$.config

"$qaffctl_bin" cids "$sock" --count >/tmp/qaffctl-control-$$.cids
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.cids
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.cids
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.cids

"$qaffctl_bin" workers "$sock" >/tmp/qaffctl-control-$$.workers
grep -q '^workers_len=0$' /tmp/qaffctl-control-$$.workers

grep -q '^packets=0$' /tmp/qaffctl-control-$$.out
grep -q '^cid_map_hit=0$' /tmp/qaffctl-control-$$.out
grep -q '^fallback=0$' /tmp/qaffctl-control-$$.out

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=
rm -f /tmp/qaffctl-control-$$.out /tmp/qaffctl-control-$$.err \
  /tmp/qaffctl-control-$$.health /tmp/qaffctl-control-$$.config \
  /tmp/qaffctl-control-$$.cids /tmp/qaffctl-control-$$.workers
