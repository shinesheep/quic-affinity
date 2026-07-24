#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BUILD_DIR" >&2
  exit 2
fi

build_dir=$1
root=/tmp/qaff-install-$$
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname "$script_dir")
unit=$repo_root/packaging/systemd/qaffd@.service
env=$repo_root/packaging/systemd/qaffd.env.example
agent_unit=$repo_root/packaging/systemd/qaff-agent@.service
agent_env=$repo_root/packaging/systemd/qaff-agent.env.example
tmpfiles=$repo_root/packaging/systemd/quic-affinity.tmpfiles

cleanup() {
  rm -rf "$root"
}
trap cleanup EXIT INT TERM

cmake --install "$build_dir" --prefix "$root/usr" >/tmp/qaff-install-$$.log
rm -f /tmp/qaff-install-$$.log

test -x "$root/usr/bin/qaffctl"
test -x "$root/usr/bin/qaff-agent"
test -x "$root/usr/sbin/qaffd"
find "$root/usr" -name libqaffinity.a -type f | grep -q .
test -f "$root/usr/include/quic_affinity/quic_affinity.h"
test -f "$root/usr/include/quic_affinity/control.h"
test -f "$root/usr/libexec/quic-affinity/qaff_reuseport.bpf.o"
test -f "$root/usr/lib/systemd/system/qaffd@.service"
test -f "$root/usr/lib/systemd/system/qaff-agent@.service"
test -f "$root/usr/lib/tmpfiles.d/quic-affinity.conf"
test -f "$root/usr/lib/sysusers.d/quic-affinity.conf"
test -f "$root/usr/share/doc/quic_affinity/README.md"
test -f "$root/usr/share/doc/quic_affinity/examples/qaffd.env.example"
test -f "$root/usr/share/doc/quic_affinity/examples/qaff-agent.env.example"

grep -q '^EnvironmentFile=/etc/quic-affinity/%i.env$' "$unit"
grep -q '^ExecStart=/usr/sbin/qaffd ' "$unit"
grep -q -- '--pin-root ${QAFF_PIN_ROOT}' "$unit"
grep -q -- '--fallback-mode ${QAFF_FALLBACK_MODE}' "$unit"
grep -q -- '--state-path ${QAFF_STATE_PATH}' "$unit"
grep -q -- '--worker-heartbeat-timeout-ms ${QAFF_WORKER_HEARTBEAT_TIMEOUT_MS}' "$unit"
grep -q -- '--passive-scan-interval-ms ${QAFF_PASSIVE_SCAN_INTERVAL_MS}' "$unit"
grep -q -- '\$QAFF_EXTRA_ARGS$' "$unit"
grep -q '^CapabilityBoundingSet=.*CAP_BPF' "$unit"
grep -q '^ReadWritePaths=.*\/sys\/fs\/bpf\/quic-affinity' "$unit"

grep -q '^QAFF_SOCKET=' "$env"
grep -q '^QAFF_BPF_OBJECT=/usr/libexec/quic-affinity/qaff_reuseport.bpf.o$' "$env"
grep -q '^QAFF_SHORT_CID_LEN=8$' "$env"
grep -q '^QAFF_FALLBACK_MODE=kernel$' "$env"
grep -q '^QAFF_WORKER_HEARTBEAT_TIMEOUT_MS=0$' "$env"
grep -q '^QAFF_PASSIVE_SCAN_INTERVAL_MS=30000$' "$env"
grep -q '^QAFF_EGRESS_CGROUP=/sys/fs/cgroup$' "$env"
grep -q '^# Passive example: QAFF_EXTRA_ARGS=--passive-affinity --egress-cgroup /sys/fs/cgroup$' "$env"
grep -q '^QAFF_EXTRA_ARGS=$' "$env"
grep -q '^QAFF_PIN_ROOT=/sys/fs/bpf/quic-affinity/listeners/udp-ipv4-127.0.0.1-4433$' "$env"
grep -q '^QAFF_STATE_PATH=/var/lib/quic-affinity/udp-ipv4-127.0.0.1-4433.state$' "$env"

grep -q '^EnvironmentFile=/etc/quic-affinity/agents/%i.env$' "$agent_unit"
grep -q '^ExecStart=/usr/bin/qaff-agent watch ' "$agent_unit"
grep -q '^CapabilityBoundingSet=CAP_SYS_PTRACE$' "$agent_unit"
grep -q '^QAFF_TARGET_PID=' "$agent_env"
grep -q '^QAFF_WORKER_ID=0$' "$agent_env"
grep -q '^QAFF_LISTEN_ADDRESS=127.0.0.1$' "$agent_env"
grep -q '^QAFF_LISTEN_PORT=4433$' "$agent_env"

grep -q '^d /run/quic-affinity ' "$tmpfiles"
grep -q '^d /var/lib/quic-affinity ' "$tmpfiles"
grep -q '^d /sys/fs/bpf/quic-affinity ' "$tmpfiles"
