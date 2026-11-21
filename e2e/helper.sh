#!/bin/bash
# The root helper's tunnel, end to end: `sudo albi-cli connect --tun` against
# gp-fake-gateway, with a real utun, routes and DNS. Checks that traffic goes
# through the tunnel (the fake answers ICMP echo for any address), that
# split and full tunnels route what they should, that DNS is published as
# configured, that a dropped tunnel reconnects, and that the network is back
# to its snapshot afterwards: after SIGTERM, and after kill -9 plus a sweep of
# the excluded-route journal.
#
#   e2e/helper.sh /path/to/albi-cli /path/to/fakegp
#
# macOS, sudo. The full-tunnel scenarios send all of this Mac's IPv4 traffic
# to the fake for a few seconds each. CI runs it.
set -u

CLI=${1:?usage: helper.sh ALBI_CLI FAKEGP}
FAKEGP=${2:?usage: helper.sh ALBI_CLI FAKEGP}
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18543
CONTROL=127.0.0.1:18544
JOURNAL="/Library/Application Support/Albi/helper-journal.json"
fails=0
results=()

[ "$(uname)" = Darwin ] || { echo "macOS only"; exit 2; }
sudo -n true || { echo "needs passwordless sudo (or run sudo -v first)"; exit 2; }
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

pass() { echo "PASS: $*"; results+=("PASS: $*"); }
fail() { echo "FAIL: $*"; results+=("FAIL: $*"); fails=$((fails + 1)); }
note() { echo "NOTE: $*"; results+=("NOTE: $*"); }

ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+-d "$3"}; }
sessions() {
  ctl GET /sessions | python3 -c "import json, sys; s = json.load(sys.stdin) or []; s = [x for x in s if not x['expired'] and not x['logged_out']]; print($1)"
}
wait_for() {
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# Routes without ARP and cloned host entries, which come and go on their own.
routes() { netstat -rn -f inet | awk 'NR > 4 && $3 !~ /[LWH]/ { print $1, $2, $3, $4 }' | sort; }
default_route() { route -n get default 2>/dev/null | awk '/gateway:|interface:/ { printf "%s ", $2 }'; }
route_if() { route -n get "$1" 2>/dev/null | awk '/interface:/ { print $2 }'; }
route_gw() { route -n get "$1" 2>/dev/null | awk '/gateway:/ { print $2 }'; }
first_resolver() { scutil --dns | awk '/^resolver #1/ { f = 1 } f && /nameserver\[0\]/ { print $3; exit }'; }
dns_state() { scutil --dns | grep -E 'nameserver|domain|search' | sort -u; }

CLI_PID=
GP_PID=
cleanup() {
  [ -n "$CLI_PID" ] && sudo kill -9 "$CLI_PID" 2>/dev/null
  [ -n "$GP_PID" ] && kill "$GP_PID" 2>/dev/null
  sudo "$CLI" sweep >/dev/null 2>&1
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

"$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
GP_PID=$!
wait_for 10 test -s "$WORK/pin" || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
printf 'test\n' >"$WORK/password"

# scenario NAME split|full term|kill9 split|full(dns)
scenario() {
  local name=$1 mode=$2 how=$3 dns=$4 log="$WORK/$1.log"
  echo
  echo "== $name: $mode tunnel, $dns DNS, stopped by $how"
  if [ "$mode" = full ]; then
    ctl PUT /config '{"access_routes": ["0.0.0.0/0"], "exclude_routes": ["203.0.113.0/24"]}' >/dev/null
  else
    ctl PUT /config '{"access_routes": ["10.99.0.0/24"], "exclude_routes": []}' >/dev/null
  fi

  local before_routes before_default before_resolver before_dns
  before_routes=$(routes)
  before_default=$(default_route)
  before_resolver=$(first_resolver)
  before_dns=$(dns_state)
  local router=${before_default%% *}

  sudo -n "$CLI" connect "$LISTEN" --tun --dns "$dns" --user test --pin "$(cat "$WORK/pin")" --second-factor 1 \
    <"$WORK/password" >"$log" 2>&1 &
  local sudo_pid=$!
  wait_for 10 grep -q 'opened pid=' "$log"
  CLI_PID=$(sed -n 's/.*opened pid=\([0-9]*\).*/\1/p' "$log" | head -1)
  local utun
  utun=$(sed -n 's/^albi: [0-9-]* [0-9:]* tun \(utun[0-9]*\) opened.*/\1/p' "$log" | head -1)
  if [ -z "$CLI_PID" ] || ! wait_for 30 grep -q 'network applied' "$log"; then
    fail "$name: tunnel did not come up"
    sed 's/^/  albi: /' "$log"
    [ -n "$CLI_PID" ] && sudo kill -9 "$CLI_PID" 2>/dev/null
    CLI_PID=
    return
  fi
  grep -E 'tun |network applied|settings' "$log" | sed 's/^/  /'

  # While up.
  if ifconfig "$utun" 2>/dev/null | grep -q 'inet 10.99.0.2 '; then pass "$name: $utun has 10.99.0.2"; else fail "$name: $utun has no 10.99.0.2"; fi
  if [ "$(route_if 10.99.0.1)" = "$utun" ]; then pass "$name: 10.99.0.1 routes into $utun"; else fail "$name: 10.99.0.1 routes via $(route_if 10.99.0.1)"; fi
  if ping -c 3 -i 0.5 -t 5 10.99.0.1 >/dev/null; then pass "$name: ping 10.99.0.1 through the tunnel"; else fail "$name: no ping reply from 10.99.0.1"; fi
  if [ "$mode" = full ]; then
    if [ "$(route_if 198.51.100.1)" = "$utun" ]; then pass "$name: other addresses route into $utun"; else fail "$name: 198.51.100.1 routes via $(route_if 198.51.100.1)"; fi
    # Only the fake answers TEST-NET-2, so a reply proves the full tunnel carries it.
    if ping -c 3 -i 0.5 -t 5 198.51.100.1 >/dev/null; then pass "$name: ping 198.51.100.1 through the full tunnel"; else fail "$name: no ping reply from 198.51.100.1"; fi
    if [ "$(route_gw 203.0.113.5)" = "$router" ]; then pass "$name: excluded 203.0.113.0/24 goes via the router $router"; else fail "$name: 203.0.113.5 goes via '$(route_gw 203.0.113.5)', not $router"; fi
    if sudo grep -q 203.0.113.0 "$JOURNAL" 2>/dev/null; then pass "$name: excluded route journaled"; else fail "$name: excluded route not in $JOURNAL"; fi
  else
    if [ "$(route_if 198.51.100.1)" != "$utun" ]; then pass "$name: other addresses stay outside"; else fail "$name: 198.51.100.1 routes into $utun on a split tunnel"; fi
  fi
  if [ "$(default_route)" = "$before_default" ]; then pass "$name: default route untouched"; else fail "$name: default route '$before_default' became '$(default_route)'"; fi
  if scutil --dns | grep -q 'nameserver\[0\] : 10.99.0.53'; then pass "$name: tunnel DNS published"; else fail "$name: 10.99.0.53 not in scutil --dns"; fi
  if [ "$dns" = full ] || [ "$mode" = full ]; then
    # Any name must go to the tunnel's DNS, in split mode too on a full
    # tunnel: its routes would capture an off-link resolver. (The runner's
    # own resolver is on its LAN, so the routes alone don't carry its queries.)
    local m0 m1
    m0=$(sessions "sum(x['packets_in'] for x in s)")
    dscacheutil -q host -a name "albi-$RANDOM.example.com" >/dev/null
    sleep 1
    m1=$(sessions "sum(x['packets_in'] for x in s)")
    if [ "$m1" -gt "$m0" ]; then pass "$name: any lookup goes to the tunnel's DNS"; else fail "$name: example.com lookup sent nothing through the tunnel"; fi
    note "$name: resolver #1 is $(first_resolver)"
  else
    if scutil --dns | grep -q 'domain *: fake.test'; then pass "$name: fake.test is a match domain"; else fail "$name: no fake.test resolver"; fi
    if [ "$(first_resolver)" = "$before_resolver" ]; then pass "$name: default resolver unchanged"; else fail "$name: resolver #1 changed to $(first_resolver)"; fi
  fi
  # A lookup in the gateway's domain must enter the tunnel (the fake doesn't
  # answer DNS, but it counts the packet).
  local n0 n1
  n0=$(sessions "sum(x['packets_in'] for x in s)")
  dscacheutil -q host -a name "albi-$RANDOM.fake.test" >/dev/null
  sleep 1
  n1=$(sessions "sum(x['packets_in'] for x in s)")
  if [ "$n1" -gt "$n0" ]; then pass "$name: fake.test lookup went into the tunnel"; else fail "$name: fake.test lookup sent nothing through the tunnel"; fi

  # The tunnel drops; the session reconnects (gateway socket pinned with --tun).
  ctl POST /tunnels/drop >/dev/null
  reconnected() { [ "$(grep -c 'state connected' "$log")" -ge 2 ]; }
  if wait_for 20 reconnected && ping -c 2 -t 5 10.99.0.1 >/dev/null; then
    pass "$name: reconnected after the tunnel dropped"
  else
    fail "$name: no reconnect after the tunnel dropped"
  fi

  # Stop.
  if [ "$how" = kill9 ]; then sudo kill -9 "$CLI_PID"; else sudo kill -TERM "$CLI_PID"; fi
  wait "$sudo_pid" 2>/dev/null
  CLI_PID=
  sleep 2 # configd reacts to a dead session asynchronously
  [ "$how" = term ] && { grep -q 'network removed' "$log" && pass "$name: removed its network on SIGTERM" || fail "$name: no 'network removed' on SIGTERM"; }

  if grep -Eq 'path changed|state (reconnecting|waiting)' "$log"; then
    echo "  session events:"
    grep -E 'path changed|state |network (applied|removed)|failed' "$log" | sed 's/^/    /'
  fi

  # After.
  if ifconfig -l | tr ' ' '\n' | grep -qx "$utun"; then fail "$name: $utun still exists"; else pass "$name: $utun is gone"; fi
  if [ "$mode" = full ] && [ "$how" = kill9 ]; then
    # The one change that outlives the process, by design, until a sweep.
    if [ "$(route_gw 203.0.113.5)" = "$router" ] && routes | grep -q '^203.0.113'; then
      note "$name: excluded route outlived kill -9, as expected"
    fi
    sudo -n "$CLI" sweep | sed 's/^/  /'
    if sudo test -e "$JOURNAL"; then fail "$name: journal still there after the sweep"; else pass "$name: sweep removed the journal"; fi
  fi
  if sudo test -e "$JOURNAL"; then fail "$name: journal left behind"; fi
  local after_routes added removed
  after_routes=$(routes)
  added=$(comm -13 <(echo "$before_routes") <(echo "$after_routes"))
  removed=$(comm -23 <(echo "$before_routes") <(echo "$after_routes"))
  if echo "$added" | grep -Eq "utun|^0/1 |^128.0/1 |^10\.99|^203\.0\.113"; then
    fail "$name: routes left behind:"
    echo "$added" | sed 's/^/    /'
  else
    pass "$name: no tunnel routes left"
  fi
  [ -n "$added$removed" ] && {
    echo "  other route changes (informational):"
    echo "$added" | sed '/^$/d; s/^/    + /'
    echo "$removed" | sed '/^$/d; s/^/    - /'
  }
  if [ "$(default_route)" = "$before_default" ]; then pass "$name: default route as before"; else fail "$name: default route was '$before_default', now '$(default_route)'"; fi
  if [ "$(dns_state)" = "$before_dns" ]; then
    pass "$name: DNS as before"
  else
    fail "$name: DNS differs from the snapshot:"
    diff <(echo "$before_dns") <(dns_state) | sed 's/^/    /'
  fi
}

scenario split-term split term split
scenario split-kill9 split kill9 split
scenario full-term full term split
scenario full-kill9 full kill9 full

echo
echo "== summary ($(sw_vers -productVersion), $(uname -m))"
printf '%s\n' "${results[@]}"
[ "$fails" -eq 0 ] && echo "all passed" || echo "$fails failed"
exit $((fails > 0))
