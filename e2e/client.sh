#!/bin/bash
# End-to-end test: albi-cli against gp-fake-gateway, no root, no utun.
# albi-cli pings through the tunnel from userspace, so this runs on a stock
# macOS runner. The same scenarios as gp-fake-gateway's e2e/run.sh with real
# openconnect, plus the ones openconnect fails.
#
#   e2e/client.sh /path/to/albi-cli /path/to/fakegp /path/to/hipreport-stub.sh
set -u

CLI=${1:?usage: client.sh ALBI_CLI FAKEGP HIP_WRAPPER}
FAKEGP=${2:?usage: client.sh ALBI_CLI FAKEGP HIP_WRAPPER}
HIP=${3:?usage: client.sh ALBI_CLI FAKEGP HIP_WRAPPER}
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18443
CONTROL=127.0.0.1:18444
fails=0

unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

cleanup() {
  [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
  [ -n "${GP_PID:-}" ] && kill "$GP_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+-d "$3"}; }

wait_for() {
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# sessions EXPR: evaluate a Python expression over the session list `s`.
sessions() {
  ctl GET /sessions | python3 -c "import json, sys; s = json.load(sys.stdin) or []; print($1)"
}
live() { echo "[x for x in s if not x['expired'] and not x['logged_out']]"; }

start_fakegp() {
  "$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" "$@" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
  GP_PID=$!
  wait_for 10 test -s "$WORK/pin" || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
}

# start_cli LOG [extra args]: connect through the portal, password on stdin,
# pinging 10.99.0.1 once a second unless NOPING=1.
start_cli() {
  local log=$1; shift
  local ping=(--ping 10.99.0.1)
  [ "${NOPING:-0}" = 1 ] && ping=()
  rm -f "$WORK/cli.exit" "$WORK/cli.pid"
  printf 'test\n' >"$WORK/password"
  # Signals go to albi-cli itself, not to this wrapper, which only records
  # the exit status. (macOS bash 3.2 needs the ${a[@]+...} form for an empty
  # array under set -u.)
  {
    "$CLI" connect "$LISTEN" --user test --pin "$(cat "$WORK/pin")" --second-factor 1 \
      ${ping[@]+"${ping[@]}"} "$@" <"$WORK/password" >"$log" 2>"$log.err" &
    echo $! >"$WORK/cli.pid"
    wait $!
    echo $? >"$WORK/cli.exit"
  } &
  wait_for 5 test -s "$WORK/cli.pid"
  CLI_PID=$(cat "$WORK/cli.pid")
}

replies() { grep -c 'ping reply' "$1" 2>/dev/null || echo 0; }
replies_above() { [ "$(replies "$1")" -gt "$2" ]; }
connected() { grep -q 'state connected' "$1"; }

wait_exit() {
  for _ in $(seq "$1"); do
    [ -s "$WORK/cli.exit" ] && { cat "$WORK/cli.exit"; return 0; }
    sleep 1
  done
  echo timeout
}

stop_cli() {
  kill -INT "$CLI_PID" 2>/dev/null
  wait_exit 15 >/dev/null
}

start_fakegp

echo "== connect, traffic, reconnect, cookie rejection"
L=$WORK/cli1.log
start_cli "$L"
if wait_for 20 replies_above "$L" 2; then pass "ICMP echo through the tunnel"; else fail "no ICMP echo"; fi
if grep -q 'settings ipv4=10.99.0.2 routes=10.99.0.0/24' "$L"; then pass "settings mapped from getconfig"; else fail "unexpected settings: $(grep settings "$L")"; fi

n=$(replies "$L")
ctl POST /tunnels/drop >/dev/null
if wait_for 20 replies_above "$L" $((n + 2)) && [ "$(sessions "max([x['tunnels'] for x in $(live)] or [0])")" -ge 2 ]; then
  pass "reconnected with the same cookie after the tunnel dropped"
else
  fail "no reconnect after the tunnel dropped"
fi

n=$(replies "$L")
kill -USR2 "$CLI_PID"
if wait_for 20 replies_above "$L" $((n + 2)) && [ "$(sessions "max([x['tunnels'] for x in $(live)] or [0])")" -ge 3 ]; then
  pass "forced reconnect (as on a network change)"
else
  fail "no reconnect after SIGUSR2"
fi

ctl POST /sessions/expire >/dev/null
code=$(wait_exit 30)
if [ "$code" = 2 ]; then pass "exited 2 (login needed) after the session expired"; else fail "after expiry: exit $code, want 2"; fi

echo "== dead peer"
# No pings here: any packet from the gateway counts as a sign of life.
L=$WORK/cli2.log
NOPING=1 start_cli "$L" --dpd 2
wait_for 20 connected "$L"
ctl PUT /config '{"ignore_keepalive": true}' >/dev/null
if wait_for 30 grep -q 'dead peer' "$L"; then pass "dead peer detected"; else fail "no dead peer detection"; fi
ctl PUT /config '{"ignore_keepalive": false}' >/dev/null
connected_twice() { [ "$(grep -c 'state connected' "$L")" -ge 2 ]; }
if wait_for 20 connected_twice; then pass "reconnected after the dead peer"; else fail "no reconnect after the dead peer"; fi
ctl PUT /config '{"ignore_keepalive": false}' >/dev/null
stop_cli

echo "== HIP report, recheck failure and retry"
ctl PUT /config '{"hip_needed": true}' >/dev/null
L=$WORK/cli3.log
start_cli "$L" --hip-wrapper "$HIP" --hip-interval 5 --hip-retry 2
wait_for 20 replies_above "$L" 1
if [ "$(sessions "sum(len(x['hip_reports'] or []) for x in s)")" -ge 1 ]; then pass "HIP report submitted"; else fail "no HIP report reached the gateway"; fi

ctl PUT /config '{"hip_check_fail": true}' >/dev/null
sleep 12
if [ ! -s "$WORK/cli.exit" ] && grep -q 'HIP check failed' "$L.err"; then
  n=$(replies "$L")
  if wait_for 10 replies_above "$L" "$n"; then pass "failed HIP rechecks did not drop the tunnel"; else fail "no traffic while HIP rechecks fail"; fi
else
  fail "a failed HIP recheck ended the session or never happened"
fi
before=$(sessions "max([x['hip_checks'] for x in $(live)] or [0])")
ctl PUT /config '{"hip_check_fail": false}' >/dev/null
hip_above() { [ "$(sessions "max([x['hip_checks'] for x in $(live)] or [0])")" -gt "$before" ]; }
if wait_for 30 hip_above; then pass "HIP recheck succeeded again after the fault cleared"; else fail "no successful HIP recheck after the fault cleared"; fi
if [ "$(sessions "max([x['tunnels'] for x in $(live)] or [0])")" = 1 ]; then pass "HIP rechecks ran beside the tunnel (one tunnel)"; else fail "HIP rechecks reopened the tunnel"; fi
ctl PUT /config '{"hip_needed": false}' >/dev/null

echo "== logout"
stop_cli
if [ "$(sessions "sum(1 for x in s if x['logged_out'])")" -ge 1 ]; then pass "SIGINT logged out"; else fail "no logout on SIGINT"; fi

echo "== re-auth before the cookie's lifetime ends"
ctl PUT /config '{"lifetime": 40}' >/dev/null
L=$WORK/cli4.log
start_cli "$L" --reauth
wait_for 20 replies_above "$L" 1
# Lead time is min(300 s, lifetime / 2) = 20 s.
if wait_for 40 grep -q 'logged in again' "$L"; then pass "logged in again before the lifetime ended"; else fail "no early re-auth"; fi
n=$(replies "$L")
if wait_for 20 replies_above "$L" "$n"; then pass "traffic flows with the new cookie"; else fail "no traffic after re-auth"; fi
sleep 25
if [ ! -s "$WORK/cli.exit" ]; then pass "still up after the first cookie's lifetime"; else fail "session ended at the first cookie's lifetime"; fi
ctl PUT /config '{"lifetime": 86400}' >/dev/null
stop_cli

if [ "$fails" -ne 0 ]; then
  echo "--- fakegp log"; tail -60 "$WORK/fakegp.log"
  for f in "$WORK"/cli*.log; do echo "--- $f"; tail -40 "$f"; echo "--- $f.err"; tail -40 "$f.err"; done
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
