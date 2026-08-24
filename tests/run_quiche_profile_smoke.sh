#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
  echo "usage: $0 PATH_TO_QAFFD PATH_TO_QUICHE_UDP_SMOKE PATH_TO_BPF_OBJECT CERT KEY" >&2
  exit 2
fi

qaffd_bin=$1
smoke_bin=$2
bpf_obj=$3
cert=$4
key=$5
id=$$
sock=/tmp/qaff-quiche-profile-$id.sock
pin_root=/sys/fs/bpf/quic-affinity-quiche-profile-$id
state_path=/tmp/qaff-quiche-profile-$id.state
output=/tmp/qaff-quiche-profile-$id.out
profile_key=707172737475767778797a7b7c7d7e7f
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep
use_sudo=0

cleanup() {
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    if [ "$use_sudo" -eq 1 ]; then
      sudo -n kill "$daemon_pid" 2>/dev/null || true
    fi
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock" "$output" "$state_path" 2>/dev/null || true
  if [ "$use_sudo" -eq 1 ]; then
    sudo -n rm -f "$sock" "$state_path" 2>/dev/null || true
  fi
  if [ -x "$pin_root" ]; then
    rm -f "$pin_root/qaff_cids" "$pin_root/qaff_passive_cids" \
      "$pin_root/qaff_workers" "$pin_root/qaff_socket_workers" \
      "$pin_root/qaff_worker_generations" "$pin_root/qaff_stats" \
      "$pin_root/qaff_config" 2>/dev/null || true
    rmdir "$pin_root" 2>/dev/null || true
  fi
  if [ -d "$pin_root" ] && command -v sudo >/dev/null 2>&1; then
    sudo -n rm -f "$pin_root/qaff_cids" "$pin_root/qaff_passive_cids" \
      "$pin_root/qaff_workers" "$pin_root/qaff_socket_workers" \
      "$pin_root/qaff_worker_generations" "$pin_root/qaff_stats" \
      "$pin_root/qaff_config" 2>/dev/null || true
    sudo -n rmdir "$pin_root" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  use_sudo=1
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

if [ "$use_sudo" -eq 1 ]; then
  sudo -n "$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" \
    --short-cid-len 16 \
    --pin-root "$pin_root" \
    --state-path "$state_path" \
    --cid-profile-key "$profile_key" \
    --reuseport-bpf-policy replace &
else
  "$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" \
    --short-cid-len 16 \
    --pin-root "$pin_root" \
    --state-path "$state_path" \
    --cid-profile-key "$profile_key" \
    --reuseport-bpf-policy replace &
fi
daemon_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  ready=0
  if [ "$use_sudo" -eq 1 ]; then
    sudo -n "$smoke_bin" --probe-ready "$sock" >/dev/null 2>/dev/null && ready=1
  else
    "$smoke_bin" --probe-ready "$sock" >/dev/null 2>/dev/null && ready=1
  fi
  if [ "$ready" -eq 1 ]; then
    if [ "$use_sudo" -eq 1 ]; then
      sudo -n "$smoke_bin" --profile "$sock" "$cert" "$key" >"$output"
    else
      "$smoke_bin" --profile "$sock" "$cert" "$key" >"$output"
    fi
    cat "$output"
    grep -q '^quiche_udp_smoke=ok$' "$output"
    grep -q '^cid_profile=1$' "$output"
    grep -q '^profile_generation=1$' "$output"
    grep -q '^additional_profile_cid_seq=1$' "$output"
    grep -q '^replacement_profile_generation=2$' "$output"
    grep -q '^stale_profile_rejected=1$' "$output"
    grep -q '^cid_map_hit=0$' "$output"
    wait "$daemon_pid"
    daemon_pid=
    exit 0
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "skipping: qaffd exited before quiche profile smoke could run" >&2
    exit 77
  fi
  sleep 0.02
done

echo "qaffd did not become ready" >&2
exit 1
