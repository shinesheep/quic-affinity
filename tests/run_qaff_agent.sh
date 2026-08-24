#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
  echo "usage: $0 QAFFD QAFFCTL QAFF_AGENT TARGET BPF_OBJECT" >&2
  exit 2
fi

qaffd_bin=$1
qaffctl_bin=$2
agent_bin=$3
target_bin=$4
bpf_obj=$5
sock=/tmp/qaff-agent-$$.sock
agent_log=/tmp/qaff-agent-$$.log
rotate_log=/tmp/qaff-agent-rotate-$$.log
prestart_log=/tmp/qaff-agent-prestart-$$.log
readiness_log=/tmp/qaff-agent-readiness-$$.log
readiness_hook=/tmp/qaff-agent-readiness-$$.sh
readiness_failure_log=/tmp/qaff-agent-readiness-failure-$$.log
config_out=/tmp/qaff-agent-$$.config
port=$((20000 + ($$ % 20000)))
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep

cleanup() {
  if [ "${agent_pid:-}" ]; then
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
  if [ "${daemon_pid:-}" ]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -f "$sock" "$agent_log" "$rotate_log" "$prestart_log" \
    "$readiness_log" \
    "$readiness_hook" "$readiness_failure_log" "$config_out"
}
trap cleanup EXIT INT TERM

if command -v sudo >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
  sudo -n setcap "$caps" "$qaffd_bin" 2>/dev/null || true
fi

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-mode kernel &
daemon_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" health "$sock" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "skipping: qaffd exited before becoming ready" >&2
    exit 77
  fi
  sleep 0.02
done
if [ "$ready" -ne 1 ]; then
  echo "qaffd did not become ready" >&2
  exit 1
fi

if "$agent_bin" run --socket "$sock" --worker-id 0 \
    --address 127.0.0.1 --port "$port" \
    --readiness-command /bin/false --readiness-timeout-ms 1000 \
    -- "$target_bin" listen "$port" >"$readiness_failure_log" 2>&1; then
  echo "qaff-agent ignored a failed initial not-ready hook" >&2
  exit 1
fi
grep -q '^qaff-agent: readiness not-ready:' "$readiness_failure_log"

printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "$1" >> "$QAFF_AGENT_TARGET_EVENT_LOG"' \
  >"$readiness_hook"
chmod 700 "$readiness_hook"
: >"$readiness_log"
export QAFF_AGENT_TARGET_EVENT_LOG="$readiness_log"

"$agent_bin" run --socket "$sock" --worker-id 0 \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 \
  --readiness-command "$readiness_hook" --readiness-timeout-ms 1000 \
  --discovery-timeout-ms 3000 -- "$target_bin" listen "$port" \
  >"$agent_log" 2>&1 &
agent_pid=$!

registered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out" &&
      grep -q '^attached=1$' "$config_out"; then
    registered=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    wait "$agent_pid" || agent_rc=$?
    agent_pid=
    cat "$agent_log" >&2 || true
    if grep -Eq 'Operation not permitted|Function not implemented|Permission denied' "$agent_log"; then
      echo "skipping: pidfd_getfd is unavailable under this security policy" >&2
      exit 77
    fi
    exit "${agent_rc:-1}"
  fi
  sleep 0.05
done
if [ "$registered" -ne 1 ]; then
  cat "$agent_log" >&2 || true
  echo "qaff-agent did not register the target socket" >&2
  exit 1
fi
test "$(sed -n '1p' "$readiness_log")" = not-ready
test "$(sed -n '2p' "$readiness_log")" = bound
test "$(sed -n '3p' "$readiness_log")" = ready
"$qaffctl_bin" workers "$sock" >"$config_out"
grep -Eq '^worker=0 .* target_pid=[1-9][0-9]* ' "$config_out"

# The agent must keep the unmodified target alive and restore its leased socket
# registration when qaffd is restarted.
kill "$daemon_pid"
wait "$daemon_pid"
daemon_pid=

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-mode kernel &
daemon_pid=$!

restored=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out" &&
      grep -q '^attached=1$' "$config_out"; then
    restored=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$agent_log" >&2 || true
    echo "qaff-agent exited while restoring a lease" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$restored" -ne 1 ]; then
  cat "$agent_log" >&2 || true
  echo "qaff-agent did not restore its lease after qaffd restart" >&2
  exit 1
fi
grep -q '^qaff-agent: restored worker_id=0 lease after qaffd disconnect$' \
  "$agent_log"
test "$(sed -n '4p' "$readiness_log")" = not-ready
test "$(sed -n '5p' "$readiness_log")" = ready

# A termination request must still run the synchronous not-ready hook before
# the agent forwards the signal to, and reaps, its managed target.
kill -TERM "$agent_pid"
agent_rc=0
wait "$agent_pid" || agent_rc=$?
agent_pid=
test "$agent_rc" -eq 143

unregistered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=0$' "$config_out"; then
    unregistered=1
    break
  fi
  sleep 0.05
done
if [ "$unregistered" -ne 1 ]; then
  cat "$agent_log" >&2 || true
  echo "qaff-agent lease outlived the target process" >&2
  exit 1
fi

grep -q '^qaff-agent: registered worker_id=0 ' "$agent_log"
test "$(sed -n '6p' "$readiness_log")" = not-ready

# The target may close and replace its listening socket without exiting. The
# agent must revoke the old lease, release its duplicate of the abandoned
# socket, discover the replacement, and register a fresh lease.
: >"$readiness_log"

"$agent_bin" run --socket "$sock" --worker-id 0 \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 \
  --readiness-command "$readiness_hook" --readiness-timeout-ms 1000 \
  --discovery-timeout-ms 3000 -- "$target_bin" rotate "$port" \
  >"$rotate_log" 2>&1 &
agent_pid=$!

registered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out"; then
    registered=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$rotate_log" >&2 || true
    echo "qaff-agent exited before rotation test registration" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$registered" -ne 1 ]; then
  cat "$rotate_log" >&2 || true
  echo "qaff-agent did not register rotation test socket" >&2
  exit 1
fi
test "$(sed -n '1p' "$readiness_log")" = not-ready
test "$(sed -n '2p' "$readiness_log")" = bound
test "$(sed -n '3p' "$readiness_log")" = ready

"$target_bin" send "$port"

revoked=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if grep -q '^qaff-agent: target socket changed; revoking worker_id=0 ' \
       "$rotate_log" &&
      "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=0$' "$config_out"; then
    revoked=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$rotate_log" >&2 || true
    echo "qaff-agent exited before revoking stale socket" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$revoked" -ne 1 ]; then
  cat "$rotate_log" >&2 || true
  echo "qaff-agent did not revoke stale socket before replacement" >&2
  exit 1
fi
test "$(sed -n '4p' "$readiness_log")" = not-ready

replaced=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60; do
  if grep -q '^qaff-agent: target socket changed; revoking worker_id=0 ' \
       "$rotate_log" &&
      grep -q '^qaff-agent: re-registered worker_id=0 ' "$rotate_log" &&
      "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out"; then
    replaced=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$rotate_log" >&2 || true
    echo "qaff-agent exited before registering replacement socket" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$replaced" -ne 1 ]; then
  cat "$rotate_log" >&2 || true
  echo "qaff-agent did not replace the stale socket registration" >&2
  exit 1
fi
test "$(sed -n '5p' "$readiness_log")" = bound
test "$(sed -n '6p' "$readiness_log")" = ready

"$target_bin" send "$port"
wait "$agent_pid"
agent_pid=
test "$(sed -n '7p' "$readiness_log")" = not-ready

unregistered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=0$' "$config_out"; then
    unregistered=1
    break
  fi
  sleep 0.05
done
if [ "$unregistered" -ne 1 ]; then
  cat "$rotate_log" >&2 || true
  echo "replacement socket lease outlived the target process" >&2
  exit 1
fi

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=

# The agent may start and discover its target before qaffd. It must remain
# not-ready and retry instead of terminating the application or exiting.
: >"$readiness_log"
"$agent_bin" run --socket "$sock" --worker-id 0 \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 \
  --readiness-command "$readiness_hook" --readiness-timeout-ms 1000 \
  --discovery-timeout-ms 3000 -- "$target_bin" listen "$port" \
  >"$prestart_log" 2>&1 &
agent_pid=$!

retrying=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if grep -q '^qaff-agent: qaffd unavailable; retrying worker_id=0 ' \
       "$prestart_log"; then
    retrying=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$prestart_log" >&2 || true
    echo "qaff-agent exited while waiting for qaffd" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$retrying" -ne 1 ]; then
  cat "$prestart_log" >&2 || true
  echo "qaff-agent did not retry before qaffd startup" >&2
  exit 1
fi

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-mode kernel &
daemon_pid=$!

registered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out"; then
    registered=1
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$prestart_log" >&2 || true
    echo "qaff-agent exited before delayed qaffd registration" >&2
    exit 1
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$prestart_log" >&2 || true
    echo "qaffd exited during delayed registration" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$registered" -ne 1 ]; then
  cat "$prestart_log" >&2 || true
  echo "qaff-agent did not register after qaffd startup" >&2
  exit 1
fi
test "$(sed -n '1p' "$readiness_log")" = not-ready
test "$(sed -n '2p' "$readiness_log")" = bound
test "$(sed -n '3p' "$readiness_log")" = ready

"$target_bin" send "$port"
wait "$agent_pid"
agent_pid=
test "$(sed -n '4p' "$readiness_log")" = not-ready

unregistered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=0$' "$config_out"; then
    unregistered=1
    break
  fi
  sleep 0.05
done
if [ "$unregistered" -ne 1 ]; then
  cat "$prestart_log" >&2 || true
  echo "delayed-start lease outlived the target" >&2
  exit 1
fi

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=
