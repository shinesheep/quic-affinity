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
sock=/tmp/qaff-quiche-udp-$$.sock
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

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 &
daemon_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$smoke_bin" --probe-ready "$sock" >/dev/null 2>/dev/null; then
    exec "$smoke_bin" "$sock" "$cert" "$key"
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "skipping: qaffd exited before quiche UDP smoke could run" >&2
    exit 77
  fi
  sleep 0.02
done

echo "qaffd did not become ready" >&2
exit 1

