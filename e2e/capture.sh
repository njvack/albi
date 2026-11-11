#!/bin/bash
# End-to-end test of gp-capture: real openconnect against gp-fake-gateway,
# captured, redacted and summarized. openconnect needs root for its tun
# device; gp-capture runs it through sudo when it is not root, so on macOS
# this also checks that it can stop openconnect through sudo and still log
# out.
#
#   e2e/capture.sh /path/to/gp-capture /path/to/fakegp /path/to/hipreport-stub.sh [/path/to/openconnect]
set -u

CAPTURE=${1:?usage: capture.sh GP_CAPTURE FAKEGP HIP_WRAPPER [OPENCONNECT]}
FAKEGP=${2:?usage: capture.sh GP_CAPTURE FAKEGP HIP_WRAPPER [OPENCONNECT]}
HIP=${3:?usage: capture.sh GP_CAPTURE FAKEGP HIP_WRAPPER [OPENCONNECT]}
OC=${4:-$(command -v openconnect)}
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18443
CONTROL=127.0.0.1:18444
fails=0

unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

cleanup() {
  [ -n "${GP_PID:-}" ] && kill "$GP_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+-d "$3"}; }
sessions() {
  ctl GET /sessions | python3 -c "import json, sys; s = json.load(sys.stdin) or []; print($1)"
}

"$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
GP_PID=$!
for _ in $(seq 10); do [ -s "$WORK/pin" ] && break; sleep 1; done
[ -s "$WORK/pin" ] || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
ctl PUT /config '{"hip_needed": true, "rekey": 3600, "lifetime": 43200, "idle_timeout": 1800,
  "client_ipv6": "fd00:99::2", "access_routes": ["10.99.0.0/24", "fd00:99::/64"]}' >/dev/null

GP_CAPTURE_PASSWORD=test "$CAPTURE" --user test --second-factor 1 --servercert "$(cat "$WORK/pin")" \
  --hip-wrapper "$HIP" --openconnect "$OC" --duration 5 --out "$WORK/out" "$LISTEN" >"$WORK/capture.out" 2>&1
code=$?
F=$WORK/out/fixtures
if [ "$code" = 0 ]; then pass "gp-capture exited 0 (leak check passed)"; else fail "gp-capture exited $code"; fi

if [ "$(sessions 'sum(1 for x in s if x["logged_out"])')" -ge 1 ]; then
  pass "openconnect logged out when gp-capture stopped it"
else
  fail "no session was logged out"
fi

for want in "lifetime: 43200 s (12 h)" "timeout (rekey): 3600 s (1 h)" "disconnect-on-idle: 1800 s (30 min)" \
            "hip-report-needed: yes" "hipreport submissions: 1, accepted: 1" "IPv6 address: yes" "access routes: 2 (1 IPv6)"; do
  if grep -qF "$want" "$F/summary.txt" 2>/dev/null; then pass "summary: $want"; else fail "summary lacks: $want"; fi
done

for label in portal-prelogin portal-getconfig gateway-login gateway-getconfig gateway-hipreportcheck gateway-hipreport tunnel-connect gateway-logout; do
  if grep -q "	$label\$" "$F/index.tsv" 2>/dev/null; then pass "captured $label"; else fail "no $label exchange"; fi
done

# Nothing the fake handed out survives redaction.
cookie=$(sessions 's[0]["authcookie"]')
leaked=0
for secret in "$cookie" "10.99.0.2" "fd00:99::2" "passwd=test" "user=test&" "<user>test</user>" "Fake gateway" "fake-portal"; do
  if grep -rqF -- "$secret" "$F"; then fail "fixtures still contain $secret"; leaked=1; fi
done
[ "$leaked" = 0 ] && pass "fixtures contain none of the fake's cookie, addresses or names"
if grep -qF "$cookie" "$WORK/out/raw/openconnect.log"; then pass "raw log kept the real values"; else fail "raw log is missing the cookie"; fi

if [ "$fails" -ne 0 ]; then
  echo "--- gp-capture output"; tail -60 "$WORK/capture.out"
  echo "--- fakegp log"; tail -20 "$WORK/fakegp.log"
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
