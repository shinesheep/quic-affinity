#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 BUILD_DIR [LISTENER_ID]" >&2
  exit 2
fi

build_dir=$1
listener_id=${2:-qaff-smoke-$$}

case "$listener_id" in
  *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-]*)
    echo "listener id may only contain ASCII letters, digits, '.', '_', ':', and '-'" >&2
    exit 2
    ;;
esac

unit="qaffd@${listener_id}.service"
env_dir=/etc/quic-affinity
env_file="${env_dir}/${listener_id}.env"
socket_path="/run/quic-affinity/${listener_id}.sock"
pin_root="/sys/fs/bpf/quic-affinity/listeners/${listener_id}"
state_path="/var/lib/quic-affinity/${listener_id}.state"
tmp_base="/tmp/qaff-systemd-smoke-$$"

if [ "$(id -u)" -ne 0 ]; then
  echo "systemd smoke must run as root; try: sudo -n $0 $*" >&2
  exit 2
fi

cleanup() {
  systemctl stop "$unit" >/dev/null 2>&1 || true
  rm -f "$env_file" "$socket_path" "$state_path"
  rm -rf "$pin_root"
  rm -f "${tmp_base}".*
}
trap cleanup EXIT INT TERM

if ! command -v systemctl >/dev/null 2>&1; then
  echo "skipping: systemctl is not available" >&2
  exit 77
fi

if ! systemctl list-units >/dev/null 2>&1; then
  echo "skipping: systemd is not running" >&2
  exit 77
fi

cmake --install "$build_dir" --prefix /usr

if command -v systemd-tmpfiles >/dev/null 2>&1; then
  if ! systemd-tmpfiles --create /usr/lib/tmpfiles.d/quic-affinity.conf; then
    echo "skipping: systemd-tmpfiles could not create quic-affinity paths" >&2
    exit 77
  fi
else
  install -d -m 0755 /run/quic-affinity
  install -d -m 0750 /var/lib/quic-affinity
  install -d -m 0700 /sys/fs/bpf/quic-affinity
  install -d -m 0700 /sys/fs/bpf/quic-affinity/listeners
fi

if ! install -d -m 0700 /sys/fs/bpf/quic-affinity/listeners >/dev/null 2>&1; then
  echo "skipping: /sys/fs/bpf/quic-affinity/listeners is not writable" >&2
  exit 77
fi

install -d -m 0755 "$env_dir"
cat >"${tmp_base}.env" <<EOF
QAFF_SOCKET=${socket_path}
QAFF_BPF_OBJECT=/usr/libexec/quic-affinity/qaff_reuseport.bpf.o
QAFF_SHORT_CID_LEN=8
QAFF_FALLBACK_WORKER=0
QAFF_WORKER_HEARTBEAT_TIMEOUT_MS=0
QAFF_PIN_ROOT=${pin_root}
QAFF_STATE_PATH=${state_path}
EOF
install -m 0644 "${tmp_base}.env" "$env_file"

systemctl daemon-reload
systemctl start "$unit"

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
         21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 \
         41 42 43 44 45 46 47 48 49 50; do
  if /usr/bin/qaffctl health "$socket_path" >"${tmp_base}.health" 2>"${tmp_base}.err"; then
    ready=1
    break
  fi
  if ! systemctl is-active --quiet "$unit"; then
    systemctl status --no-pager "$unit" >&2 || true
    cat "${tmp_base}.err" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  systemctl status --no-pager "$unit" >&2 || true
  cat "${tmp_base}.err" >&2 || true
  echo "qaffd systemd service did not become ready" >&2
  exit 1
fi

grep -q '^ok=1$' "${tmp_base}.health"
grep -q '^attached=0$' "${tmp_base}.health"
grep -q '^worker_count=0$' "${tmp_base}.health"
grep -q '^cid_map_count=0$' "${tmp_base}.health"
grep -q '^cid_owner_count=0$' "${tmp_base}.health"
grep -q '^cid_index_mismatch=0$' "${tmp_base}.health"

/usr/bin/qaffctl config "$socket_path" >"${tmp_base}.config"
grep -q '^short_cid_len=8$' "${tmp_base}.config"
grep -q '^attached=0$' "${tmp_base}.config"
grep -q '^worker_count=0$' "${tmp_base}.config"
grep -q '^fallback_worker_id=0$' "${tmp_base}.config"
grep -q '^cid_map_count=0$' "${tmp_base}.config"
grep -q '^cid_owner_count=0$' "${tmp_base}.config"
grep -q '^cid_index_mismatch=0$' "${tmp_base}.config"
grep -q "^pin_root=${pin_root}$" "${tmp_base}.config"
grep -q "^state_path=${state_path}$" "${tmp_base}.config"

/usr/bin/qaffctl workers "$socket_path" >"${tmp_base}.workers"
grep -q '^workers_len=0$' "${tmp_base}.workers"

/usr/bin/qaffctl cids "$socket_path" --count >"${tmp_base}.cids"
grep -q '^cid_map_count=0$' "${tmp_base}.cids"
grep -q '^cid_owner_count=0$' "${tmp_base}.cids"
grep -q '^cid_index_mismatch=0$' "${tmp_base}.cids"

/usr/bin/qaffctl stats "$socket_path" >"${tmp_base}.stats"
grep -q '^packets=0$' "${tmp_base}.stats"
grep -q '^cid_map_hit=0$' "${tmp_base}.stats"
grep -q '^fallback=0$' "${tmp_base}.stats"

systemctl stop "$unit"
echo "systemd smoke passed for ${unit}"
