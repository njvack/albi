#!/bin/bash
# End-to-end test of diagnostics mode and gateway scenarios: albi-cli against
# gp-fake-gateway, no root, no utun (as e2e/client.sh).
#
#   e2e/diagnostics.sh ALBI_CLI ALBI_DIAG FAKEGP SCENARIOS_DIR
#
# 1. An outage that isn't recovered writes a redacted incident file, which
#    albi-diag checks, replays and turns into a scenario draft.
# 2. That draft, loaded into a fresh fake, makes the client fail the same way.
# 3. Every scenario in SCENARIOS_DIR (gp-fake-gateway/scenarios) passes.
set -u

CLI=${1:?usage: diagnostics.sh ALBI_CLI ALBI_DIAG FAKEGP SCENARIOS_DIR}
DIAG=${2:?usage: diagnostics.sh ALBI_CLI ALBI_DIAG FAKEGP SCENARIOS_DIR}
FAKEGP=${3:?usage: diagnostics.sh ALBI_CLI ALBI_DIAG FAKEGP SCENARIOS_DIR}
SCENARIOS=${4:?usage: diagnostics.sh ALBI_CLI ALBI_DIAG FAKEGP SCENARIOS_DIR}
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18543
CONTROL=127.0.0.1:18544
fails=0

unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

cleanup() {
  stop_all
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
skip() { echo "SKIP: $*"; }
ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+--data-binary "$3"}; }

wait_for() {
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

start_fakegp() {
  rm -f "$WORK/pin"
  "$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" "$@" >"$WORK/fakegp.out" 2>>"$WORK/fakegp.log" &
  GP_PID=$!
  wait_for 10 test -s "$WORK/pin" || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
}

# start_cli LOG [extra args]: as in client.sh, with diagnostics on.
start_cli() {
  local log=$1; shift
  rm -f "$WORK/cli.exit" "$WORK/cli.pid"
  printf 'test\n' >"$WORK/password"
  {
    "$CLI" connect "$LISTEN" --user test --pin "$(cat "$WORK/pin")" --second-factor 1 --ping 10.99.0.1 \
      --diagnostics "$DIR" "$@" <"$WORK/password" >"$log" 2>"$log.err" &
    echo $! >"$WORK/cli.pid"
    wait $!
    echo $? >"$WORK/cli.exit"
  } &
  wait_for 5 test -s "$WORK/cli.pid"
  CLI_PID=$(cat "$WORK/cli.pid")
}

stop_all() {
  [ -n "${CLI_PID:-}" ] && kill -INT "$CLI_PID" 2>/dev/null
  for _ in $(seq 10); do [ -s "$WORK/cli.exit" ] && break; sleep 1; done
  [ -n "${GP_PID:-}" ] && kill "$GP_PID" 2>/dev/null
  wait 2>/dev/null
  CLI_PID= GP_PID=
}

replies() { grep -c 'ping reply' "$1" 2>/dev/null || echo 0; }
replies_above() { [ "$(replies "$1")" -gt "$2" ]; }
connected() { grep -q 'state connected' "$1"; }
incidents() { ls "$DIR"/albi-incident-*.json 2>/dev/null | wc -l | tr -d ' '; }
incidents_above() { [ "$(incidents)" -gt "$1" ]; }
newest() { ls -t "$DIR"/albi-incident-*.json | head -1; }
json() { python3 -c "import json, sys; d = json.load(open(sys.argv[1])); print($2)" "$1"; }
cookie() { ctl GET /sessions | python3 -c "import json, sys; print(' '.join(x['cookie'] for x in json.load(sys.stdin) or []))"; }

echo "== an unrecovered outage writes a redacted incident file"
DIR=$WORK/diag1
start_fakegp
L=$WORK/cli1.log
start_cli "$L" --diag-grace 3 --dpd 2
if wait_for 20 replies_above "$L" 1; then pass "connected with diagnostics mode on"; else fail "no traffic with diagnostics mode on"; fi
COOKIES=$(cookie)

if ctl PUT /scenario '{"rules": []}' >/dev/null 2>&1; then
  ctl PUT /scenario '{"name": "refuse tunnels", "rules": [{"when": {"request": "tunnel", "from": 1}, "respond": {"status": 503}}]}' >/dev/null
  ctl POST /tunnels/drop >/dev/null
else
  # An older fake without scenarios: stall every request instead.
  ctl PUT /config '{"stall_seconds": 8}' >/dev/null
  ctl POST /tunnels/drop >/dev/null
fi
if wait_for 30 incidents_above 0; then pass "incident file written"; else fail "no incident file"; fi
F=$(newest 2>/dev/null)
if [ -n "$F" ]; then
  if grep -q 'diagnostics: incident' "$L"; then pass "albi-cli reported the file"; else fail "no diagnostics line in the log"; fi
  scrub=()
  for c in $COOKIES; do scrub+=(--scrub "$c"); done
  if "$DIAG" check "$F" ${scrub[@]+"${scrub[@]}"} >"$WORK/check.out"; then pass "albi-diag check: nothing left to redact"; else fail "albi-diag check: $(cat "$WORK/check.out")"; fi
  for c in $COOKIES; do grep -q "$c" "$F" && fail "the gateway's cookie is in the incident file"; done
  if [ "$(json "$F" "d['header']['redaction']['withheld']")" = 0 ]; then pass "leak check withheld nothing"; else fail "leak check withheld values"; fi
  if "$DIAG" replay "$F" >"$WORK/replay.out"; then pass "replay matches the recording"; else fail "replay: $(cat "$WORK/replay.out")"; fi
  "$DIAG" summary "$F" >"$WORK/summary.out" && pass "albi-diag summary" || fail "albi-diag summary"
  "$DIAG" scenario "$F" --name "drafted in e2e" >"$WORK/draft.json"
  if python3 -c "import json, sys; d = json.load(open(sys.argv[1])); assert d['rules']" "$WORK/draft.json"; then
    pass "scenario drafted with $(json "$WORK/draft.json" "len(d['rules'])") rules"
  else
    fail "empty scenario draft"
  fi
fi

ctl PUT /scenario '{"rules": []}' >/dev/null 2>&1
ctl PUT /config '{"stall_seconds": 0}' >/dev/null
outcome() { [ "$(json "$F" "d['header'].get('outcome', '')")" = "connected again" ]; }
if [ -n "$F" ] && wait_for 60 outcome; then pass "incident file rewritten once reconnected"; else fail "incident file has no outcome"; fi

n=$(incidents)
kill -USR1 "$CLI_PID"
if wait_for 10 incidents_above "$n"; then pass "SIGUSR1 saved a file while connected"; else fail "SIGUSR1 saved nothing"; fi
stop_all

if ! "$FAKEGP" -h 2>&1 | grep -q -- -scenario; then
  skip "this fakegp has no -scenario; scenario checks skipped"
else
  echo "== the drafted scenario reproduces the incident"
  if [ -s "$WORK/draft.json" ]; then
    DIR=$WORK/diag2
    start_fakegp -scenario "$WORK/draft.json"
    L=$WORK/cli2.log
    start_cli "$L" --diag-grace 3 --dpd 2
    if wait_for 30 incidents_above 0; then pass "the draft made the client fail the same way"; else fail "the draft did not reproduce an incident"; fi
    stop_all
  fi

  echo "== scenarios in $SCENARIOS"
  for S in "$SCENARIOS"/*.json; do
    [ -e "$S" ] || { skip "no scenarios"; break; }
    name=$(basename "$S" .json)
    within=$(json "$S" "d.get('expect', {}).get('connected_within', 60)")
    DIR=$WORK/scn-$name
    start_fakegp -scenario "$S"
    L=$WORK/scn-$name.log
    start_cli "$L" --dpd 2 --hip-interval 5 --hip-retry 2
    # Every rule has fired as far as it goes (the last of a range).
    all_fired() {
      ctl GET /scenario | python3 -c '
import json, sys
st = json.load(sys.stdin)
fired = {}
for f in st["fired"] or []:
    fired[f["rule"]] = max(fired.get(f["rule"], 0), f["n"])
for i, r in enumerate(st["rules"] or [], 1):
    w = r["when"]
    want = w.get("nth") or w.get("to") or w.get("from") or 1
    if fired.get(i, 0) < want:
        sys.exit(1)
'
    }
    if ! wait_for 120 all_fired; then
      fail "$name: rules never all fired: $(ctl GET /scenario | tr -d '\n' | cut -c1-300)"
      stop_all
      continue
    fi
    n=$(replies "$L")
    if wait_for "$within" replies_above "$L" "$((n + 1))"; then
      pass "$name: traffic flows within ${within} s of the last fault"
    else
      fail "$name: no traffic within ${within} s of the last fault"
    fi
    stop_all
  done
fi

if [ "$fails" -ne 0 ]; then
  echo "--- fakegp log"; tail -60 "$WORK/fakegp.log"
  for f in "$WORK"/cli*.log "$WORK"/scn-*.log; do [ -e "$f" ] || continue; echo "--- $f"; tail -30 "$f"; echo "--- $f.err"; tail -30 "$f.err"; done
  for f in "$WORK"/diag*/albi-incident-*.json; do [ -e "$f" ] || continue; echo "--- $f"; head -80 "$f"; done
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
