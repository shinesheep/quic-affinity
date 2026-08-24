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
key_file=/tmp/qaffctl-control-$$.profile-key
validation_log=/tmp/qaffctl-control-$$.validation
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

cleanup() {
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock" "$key_file" "$validation_log"
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

printf '%s\n' 707172737475767778797a7b7c7d7e7f >"$key_file"
chmod 600 "$key_file"

set +e
"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  >"$validation_log" 2>&1
validation_rc=$?
set -e
if [ "$validation_rc" -ne 2 ]; then
  cat "$validation_log" >&2 || true
  echo "qaffd accepted an implicit reuseport BPF replacement policy" >&2
  exit 1
fi
grep -q '^qaffd: --reuseport-bpf-policy replace is required because Linux attach replaces the current group program$' \
  "$validation_log"

set +e
"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-worker 4096 >"$validation_log" 2>&1
validation_rc=$?
set -e
if [ "$validation_rc" -ne 2 ]; then
  cat "$validation_log" >&2 || true
  echo "qaffd accepted an out-of-range fixed fallback worker" >&2
  exit 1
fi
grep -q '^qaffd: --fallback-worker must be less than 4096$' "$validation_log"

set +e
"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 12 \
  --reuseport-bpf-policy replace \
  --cid-profile-v2-key-file "$key_file" \
  --cid-profile-v2-config-id 7 >"$validation_log" 2>&1
validation_rc=$?
set -e
if [ "$validation_rc" -ne 2 ]; then
  cat "$validation_log" >&2 || true
  echo "qaffd accepted profile v2 without durable worker generations" >&2
  exit 1
fi
grep -q '^qaffd: CID profile v2 requires --pin-root and --state-path$' \
  "$validation_log"
grep -q '^Usage: qaffd ' "$validation_log"

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace &
daemon_pid=$!

fixed_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" stats "$sock" >/dev/null 2>/dev/null; then
    fixed_ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "skipping: fixed-fallback qaffd exited before qaffctl could connect" >&2
    exit 77
  fi
  sleep 0.02
done
if [ "$fixed_ready" -ne 1 ]; then
  echo "fixed-fallback qaffd did not become ready" >&2
  exit 1
fi

set +e
"$qaffctl_bin" health "$sock" >/tmp/qaffctl-control-$$.fixed-health
fixed_health_rc=$?
set -e
if [ "$fixed_health_rc" -ne 1 ]; then
  cat /tmp/qaffctl-control-$$.fixed-health >&2 || true
  echo "qaffctl health accepted an unavailable fixed fallback" >&2
  exit 1
fi
grep -q '^ok=0$' /tmp/qaffctl-control-$$.fixed-health
grep -q '^fallback_available=0$' /tmp/qaffctl-control-$$.fixed-health
"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-worker 1 \
  --fallback-mode kernel \
  --passive-affinity \
  --passive-min-confidence 2 &
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
grep -q '^fallback_available=1$' /tmp/qaffctl-control-$$.health
grep -q '^attached=0$' /tmp/qaffctl-control-$$.health
grep -q '^worker_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.health
grep -q '^passive_entry_count=0$' /tmp/qaffctl-control-$$.health
grep -q '^passive_entry_capacity=1048576$' /tmp/qaffctl-control-$$.health
grep -q '^passive_cleanup_error_count=0$' /tmp/qaffctl-control-$$.health

"$qaffctl_bin" config "$sock" >/tmp/qaffctl-control-$$.config
grep -q '^short_cid_len=8$' /tmp/qaffctl-control-$$.config
grep -q '^cid_profile_v2_enabled=0$' /tmp/qaffctl-control-$$.config
grep -q '^cid_profile_v2_config_id=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_affinity_enabled=1$' /tmp/qaffctl-control-$$.config
grep -q '^passive_min_confidence=2$' /tmp/qaffctl-control-$$.config
grep -q '^egress_attached=0$' /tmp/qaffctl-control-$$.config
grep -q '^attached=0$' /tmp/qaffctl-control-$$.config
grep -q '^worker_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^fallback_mode=kernel$' /tmp/qaffctl-control-$$.config
grep -q '^fallback_worker_id=1$' /tmp/qaffctl-control-$$.config
grep -q '^fallback_available=1$' /tmp/qaffctl-control-$$.config
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_entry_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_entry_capacity=1048576$' /tmp/qaffctl-control-$$.config
grep -q '^passive_expired_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_worker_purged_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_expiry_initialized_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_cleanup_error_count=0$' /tmp/qaffctl-control-$$.config
grep -q '^passive_scan_interval_ms=30000$' /tmp/qaffctl-control-$$.config
grep -q '^pin_root=$' /tmp/qaffctl-control-$$.config
grep -q '^state_path=$' /tmp/qaffctl-control-$$.config

if "$qaffctl_bin" register-passive-cid "$sock" 0 deadbeef high egress \
  >/tmp/qaffctl-control-$$.passive 2>/tmp/qaffctl-control-$$.passive.err; then
  echo "register-passive-cid unexpectedly succeeded without a worker" >&2
  exit 1
fi
grep -q '^qaff_control_register_passive_cid:' /tmp/qaffctl-control-$$.passive.err

if "$qaffctl_bin" retire-passive-cid "$sock" deadbeef \
  >/tmp/qaffctl-control-$$.passive-retire 2>/tmp/qaffctl-control-$$.passive-retire.err; then
  echo "retire-passive-cid unexpectedly succeeded for missing CID" >&2
  exit 1
fi
grep -q '^qaff_control_retire_passive_cid:' /tmp/qaffctl-control-$$.passive-retire.err

"$qaffctl_bin" cids "$sock" --count >/tmp/qaffctl-control-$$.cids
grep -q '^cid_map_count=0$' /tmp/qaffctl-control-$$.cids
grep -q '^cid_owner_count=0$' /tmp/qaffctl-control-$$.cids
grep -q '^cid_index_mismatch=0$' /tmp/qaffctl-control-$$.cids

"$qaffctl_bin" workers "$sock" >/tmp/qaffctl-control-$$.workers
grep -q '^workers_len=0$' /tmp/qaffctl-control-$$.workers

grep -q '^packets=0$' /tmp/qaffctl-control-$$.out
grep -q '^cid_map_hit=0$' /tmp/qaffctl-control-$$.out
grep -q '^cid_profile_hit=0$' /tmp/qaffctl-control-$$.out
grep -q '^cid_profile_reject=0$' /tmp/qaffctl-control-$$.out
grep -q '^fallback=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_reject_expired=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_parse_miss=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_not_udp=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_zero_length_scid=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_too_long_scid=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_socket_cookie_hit=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_socket_cookie_miss=0$' /tmp/qaffctl-control-$$.out
grep -q '^passive_egress_map_update_error=0$' /tmp/qaffctl-control-$$.out
grep -q '^cid_map_reject_generation=0$' /tmp/qaffctl-control-$$.out

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=
rm -f /tmp/qaffctl-control-$$.out /tmp/qaffctl-control-$$.err \
  /tmp/qaffctl-control-$$.fixed-health \
  /tmp/qaffctl-control-$$.health /tmp/qaffctl-control-$$.config \
  /tmp/qaffctl-control-$$.cids /tmp/qaffctl-control-$$.workers \
  /tmp/qaffctl-control-$$.passive /tmp/qaffctl-control-$$.passive.err \
  /tmp/qaffctl-control-$$.passive-retire \
  /tmp/qaffctl-control-$$.passive-retire.err
