#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
  echo "usage: $0 QAFFD QAFFCTL QAFF_AGENT BLACKBOX BPF_OBJECT CERT KEY" >&2
  exit 2
fi

qaffd_bin=$1
qaffctl_bin=$2
agent_bin=$3
blackbox_bin=$4
bpf_obj=$5
cert=$6
key=$7
id=$$
sock=/tmp/qaff-quiche-agent-$id.sock
daemon_log=/tmp/qaff-quiche-agent-$id.daemon.log
agent0_log=/tmp/qaff-quiche-agent-$id.agent0.log
agent1_log=/tmp/qaff-quiche-agent-$id.agent1.log
client_log=/tmp/qaff-quiche-agent-$id.client.log
client2_log=/tmp/qaff-quiche-agent-$id.client2.log
client3_log=/tmp/qaff-quiche-agent-$id.client3.log
replacement_log=/tmp/qaff-quiche-agent-$id.replacement.log
config_out=/tmp/qaff-quiche-agent-$id.config
stats_out=/tmp/qaff-quiche-agent-$id.stats
readiness_hook=/tmp/qaff-quiche-agent-$id.readiness.sh
readiness0_log=/tmp/qaff-quiche-agent-$id.readiness0.log
readiness1_log=/tmp/qaff-quiche-agent-$id.readiness1.log
port=$((24000 + (id % 16000)))
caps=cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep
cgroup_path=/sys/fs/cgroup

cleanup() {
  for pid in "${agent0_pid:-}" "${agent1_pid:-}" \
      "${replacement_pid:-}" "${daemon_pid:-}"; do
    if [ "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$sock" "$daemon_log" "$agent0_log" "$agent1_log" \
    "$client_log" "$client2_log" "$client3_log" "$replacement_log" \
    "$config_out" "$stats_out" "$readiness_hook" \
    "$readiness0_log" "$readiness1_log"
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
  --fallback-mode kernel \
  --passive-affinity \
  --egress-cgroup "$cgroup_path" >"$daemon_log" 2>&1 &
daemon_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$daemon_log" >&2 || true
    echo "skipping: qaffd could not attach black-box dataplane" >&2
    exit 77
  fi
  sleep 0.02
done
if [ "$ready" -ne 1 ]; then
  cat "$daemon_log" >&2 || true
  echo "qaffd did not become ready" >&2
  exit 1
fi
grep -q '^fallback_mode=kernel$' "$config_out"
grep -q '^passive_affinity_enabled=1$' "$config_out"
grep -q '^egress_attached=1$' "$config_out"

printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "$1" >> "$QAFF_AGENT_TARGET_EVENT_LOG"' \
  >"$readiness_hook"
chmod 700 "$readiness_hook"
: >"$readiness0_log"
: >"$readiness1_log"

QAFF_AGENT_TARGET_EVENT_LOG="$readiness0_log" \
  "$agent_bin" run --socket "$sock" --worker-id 0 \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 --discovery-timeout-ms 3000 \
  --readiness-command "$readiness_hook" --readiness-timeout-ms 1000 -- \
  "$blackbox_bin" server 0 "$port" "$cert" "$key" \
  >"$agent0_log" 2>&1 &
agent0_pid=$!

QAFF_AGENT_TARGET_EVENT_LOG="$readiness1_log" \
  "$agent_bin" run --socket "$sock" --worker-id 1 \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 --discovery-timeout-ms 3000 \
  --readiness-command "$readiness_hook" --readiness-timeout-ms 1000 -- \
  "$blackbox_bin" server 1 "$port" "$cert" "$key" \
  >"$agent1_log" 2>&1 &
agent1_pid=$!

registered=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=2$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out" &&
      grep -q '^attached=1$' "$config_out"; then
    registered=1
    break
  fi
  if ! kill -0 "$agent0_pid" 2>/dev/null ||
      ! kill -0 "$agent1_pid" 2>/dev/null; then
    cat "$agent0_log" "$agent1_log" >&2 || true
    if grep -Eq 'Operation not permitted|Function not implemented|Permission denied' \
        "$agent0_log" "$agent1_log"; then
      echo "skipping: pidfd_getfd is unavailable under this security policy" >&2
      exit 77
    fi
    echo "qaff-agent exited before both workers registered" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$registered" -ne 1 ]; then
  cat "$agent0_log" "$agent1_log" >&2 || true
  echo "qaff-agent did not register both black-box workers" >&2
  exit 1
fi
test "$(sed -n '1p' "$readiness0_log")" = not-ready
test "$(sed -n '2p' "$readiness0_log")" = ready
test "$(sed -n '1p' "$readiness1_log")" = not-ready
test "$(sed -n '2p' "$readiness1_log")" = ready

# Keep both unmodified quiche workers alive while qaffd restarts. Each agent
# must withdraw readiness before it restores the same socket lease.
kill "$daemon_pid"
wait "$daemon_pid"
daemon_pid=

"$qaffd_bin" --socket "$sock" --bpf "$bpf_obj" --short-cid-len 8 \
  --reuseport-bpf-policy replace \
  --fallback-mode kernel \
  --passive-affinity \
  --egress-cgroup "$cgroup_path" >>"$daemon_log" 2>&1 &
daemon_pid=$!

restored=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=2$' "$config_out" &&
      grep -q '^recovering_worker_count=0$' "$config_out" &&
      grep -q '^attached=1$' "$config_out"; then
    restored=1
    break
  fi
  if ! kill -0 "$agent0_pid" 2>/dev/null ||
      ! kill -0 "$agent1_pid" 2>/dev/null ||
      ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$daemon_log" "$agent0_log" "$agent1_log" >&2 || true
    echo "black-box workers did not survive qaffd restart" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$restored" -ne 1 ]; then
  cat "$daemon_log" "$agent0_log" "$agent1_log" >&2 || true
  echo "qaff-agent did not restore both black-box workers" >&2
  exit 1
fi
grep -q '^qaff-agent: restored worker_id=0 lease after qaffd disconnect$' \
  "$agent0_log"
grep -q '^qaff-agent: restored worker_id=1 lease after qaffd disconnect$' \
  "$agent1_log"
test "$(sed -n '3p' "$readiness0_log")" = not-ready
test "$(sed -n '4p' "$readiness0_log")" = ready
test "$(sed -n '3p' "$readiness1_log")" = not-ready
test "$(sed -n '4p' "$readiness1_log")" = ready
"$qaffctl_bin" workers "$sock" >"$config_out"
worker0_generation=$(sed -n \
  's/^worker=0 generation=\([0-9][0-9]*\).*/\1/p' "$config_out")
worker1_generation=$(sed -n \
  's/^worker=1 generation=\([0-9][0-9]*\).*/\1/p' "$config_out")
if [ -z "$worker0_generation" ] || [ -z "$worker1_generation" ]; then
  cat "$config_out" >&2
  echo "could not capture restored worker generations" >&2
  exit 1
fi

if ! "$blackbox_bin" client "$port" >"$client_log" 2>&1; then
  cat "$client_log" "$agent0_log" "$agent1_log" >&2 || true
  exit 1
fi

server_completed=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  completed_count=$(grep -l '^blackbox_server=ok$' \
    "$agent0_log" "$agent1_log" 2>/dev/null | wc -l)
  if [ "$completed_count" -eq 1 ]; then
    server_completed=1
    break
  fi
  sleep 0.05
done
if [ "$server_completed" -ne 1 ]; then
  cat "$client_log" "$agent0_log" "$agent1_log" >&2 || true
  echo "migration packet did not return to exactly one black-box worker" >&2
  exit 1
fi

"$qaffctl_bin" stats "$sock" >"$stats_out"
passive_learn=$(sed -n 's/^passive_egress_learn=//p' "$stats_out")
passive_hit=$(sed -n 's/^passive_hit=//p' "$stats_out")
fallback=$(sed -n 's/^fallback=//p' "$stats_out")
if [ -z "$passive_learn" ] || [ "$passive_learn" -lt 1 ] ||
    [ -z "$passive_hit" ] || [ "$passive_hit" -lt 1 ] ||
    [ -z "$fallback" ] || [ "$fallback" -lt 1 ]; then
  cat "$stats_out" "$daemon_log" >&2 || true
  echo "black-box passive counters did not prove learn/hit/fallback" >&2
  exit 1
fi

cat "$client_log"
grep -h -E '^(blackbox_server|worker_id|client_source_port_.*)=' \
  "$agent0_log" "$agent1_log"
printf 'passive_egress_learn=%s\n' "$passive_learn"
printf 'passive_hit=%s\n' "$passive_hit"
printf 'fallback=%s\n' "$fallback"

# The worker that owned the first connection now exits. Re-register a fresh
# process under the same worker ID and prove its generation advances.
if grep -q '^worker_id=0$' "$agent0_log"; then
  selected_worker=0
  selected_generation=$worker0_generation
  old_scid=$(sed -n 's/^server_scid=//p' "$agent0_log")
  wait "$agent0_pid"
  agent0_pid=
else
  selected_worker=1
  selected_generation=$worker1_generation
  old_scid=$(sed -n 's/^server_scid=//p' "$agent1_log")
  wait "$agent1_pid"
  agent1_pid=
fi
if [ -z "$old_scid" ]; then
  echo "selected black-box worker did not report its server CID" >&2
  exit 1
fi

withdrawn=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=1$' "$config_out"; then
    withdrawn=1
    break
  fi
  sleep 0.05
done
if [ "$withdrawn" -ne 1 ]; then
  echo "exited black-box worker lease was not withdrawn" >&2
  exit 1
fi

"$agent_bin" run --socket "$sock" --worker-id "$selected_worker" \
  --address 127.0.0.1 --port "$port" --heartbeat-ms 50 \
  --socket-check-ms 50 --discovery-timeout-ms 3000 -- \
  "$blackbox_bin" server "$selected_worker" "$port" "$cert" "$key" \
  >"$replacement_log" 2>&1 &
replacement_pid=$!

replacement_registered=0
replacement_generation=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40; do
  if "$qaffctl_bin" config "$sock" >"$config_out" 2>/dev/null &&
      grep -q '^worker_count=2$' "$config_out" &&
      "$qaffctl_bin" workers "$sock" >"$config_out" 2>/dev/null; then
    replacement_generation=$(sed -n \
      "s/^worker=$selected_worker generation=\\([0-9][0-9]*\\).*/\\1/p" \
      "$config_out")
    if [ -n "$replacement_generation" ] &&
        [ "$replacement_generation" -eq $((selected_generation + 1)) ]; then
      replacement_registered=1
      break
    fi
  fi
  if ! kill -0 "$replacement_pid" 2>/dev/null; then
    cat "$replacement_log" >&2 || true
    echo "replacement black-box worker exited before registration" >&2
    exit 1
  fi
  sleep 0.05
done
if [ "$replacement_registered" -ne 1 ]; then
  cat "$replacement_log" "$config_out" >&2 || true
  echo "replacement worker generation did not advance exactly once" >&2
  exit 1
fi

"$qaffctl_bin" stats "$sock" >"$stats_out"
hit_before_probe=$(sed -n 's/^passive_hit=//p' "$stats_out")
fallback_before_probe=$(sed -n 's/^fallback=//p' "$stats_out")
"$blackbox_bin" probe "$port" "$old_scid"
sleep 0.05
"$qaffctl_bin" stats "$sock" >"$stats_out"
hit_after_probe=$(sed -n 's/^passive_hit=//p' "$stats_out")
fallback_after_probe=$(sed -n 's/^fallback=//p' "$stats_out")
if [ "$hit_after_probe" -ne "$hit_before_probe" ] ||
    [ "$fallback_after_probe" -ne $((fallback_before_probe + 1)) ]; then
  cat "$stats_out" >&2
  echo "retired CID remained passively routable after worker replacement" >&2
  exit 1
fi

# The remaining original worker may win the first new kernel hash. If so, it
# exits after its successful connection and the second client deterministically
# exercises the replacement worker.
"$blackbox_bin" client "$port" >"$client2_log"
replacement_completed=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if grep -q '^blackbox_server=ok$' "$replacement_log"; then
    replacement_completed=1
    break
  fi
  sleep 0.05
done
if [ "$replacement_completed" -ne 1 ]; then
  remaining_log=$agent0_log
  remaining_pid=${agent0_pid:-}
  if [ "$selected_worker" -eq 0 ]; then
    remaining_log=$agent1_log
    remaining_pid=${agent1_pid:-}
  fi
  if ! grep -q '^blackbox_server=ok$' "$remaining_log"; then
    cat "$client2_log" "$remaining_log" "$replacement_log" >&2 || true
    echo "new connection reached neither live black-box worker" >&2
    exit 1
  fi
  if [ "$remaining_pid" ]; then
    wait "$remaining_pid"
    if [ "$selected_worker" -eq 0 ]; then
      agent1_pid=
    else
      agent0_pid=
    fi
  fi
  "$blackbox_bin" client "$port" >"$client3_log"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q '^blackbox_server=ok$' "$replacement_log"; then
      replacement_completed=1
      break
    fi
    sleep 0.05
  done
fi
if [ "$replacement_completed" -ne 1 ]; then
  cat "$client2_log" "$client3_log" "$replacement_log" >&2 || true
  echo "replacement worker did not learn a new real QUIC connection" >&2
  exit 1
fi

new_scid=$(sed -n 's/^server_scid=//p' "$replacement_log")
if [ -z "$new_scid" ] || [ "$new_scid" = "$old_scid" ]; then
  cat "$replacement_log" >&2 || true
  echo "replacement worker did not issue a fresh server CID" >&2
  exit 1
fi
"$qaffctl_bin" stats "$sock" >"$stats_out"
final_hit=$(sed -n 's/^passive_hit=//p' "$stats_out")
final_learn=$(sed -n 's/^passive_egress_learn=//p' "$stats_out")
if [ "$final_hit" -le "$hit_after_probe" ] ||
    [ "$final_learn" -le "$passive_learn" ]; then
  cat "$stats_out" "$replacement_log" >&2 || true
  echo "replacement worker did not relearn passive QUIC affinity" >&2
  exit 1
fi
printf 'replacement_worker=%s\n' "$selected_worker"
printf 'replacement_generation=%s\n' "$replacement_generation"
printf 'stale_cid_fallback=1\n'
printf 'replacement_passive_hit=%s\n' "$final_hit"

kill "${agent0_pid:-}" "${agent1_pid:-}" "$replacement_pid" \
  2>/dev/null || true
if [ "${agent0_pid:-}" ]; then wait "$agent0_pid" 2>/dev/null || true; fi
if [ "${agent1_pid:-}" ]; then wait "$agent1_pid" 2>/dev/null || true; fi
wait "$replacement_pid" 2>/dev/null || true
agent0_pid=
agent1_pid=
replacement_pid=

"$qaffctl_bin" stop "$sock"
wait "$daemon_pid"
daemon_pid=
