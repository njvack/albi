#!/bin/bash
# Root-helper probe: does everything albi-netprobe changes (utun, its
# address, routes on it, temporary DNS keys) vanish when the process ends,
# cleanly or by kill -9, with no cleanup code? And while it's up, does the
# system resolver use the tunnel's DNS (full tunnel: as the default resolver;
# split: only for the match domain), and does a socket pinned to the physical
# interface still get out past 0/1 and 128/1?
#
#   e2e/netprobe.sh /path/to/albi-netprobe
#
# macOS, sudo. Full-tunnel scenarios cut this Mac's network for a few
# seconds each. CI runs it; on your own Mac it asks for your password once.
# NETPROBE_CHECK_HOST sets the IPv4 address the pinned-socket check dials
# (port 443; default 1.1.1.1).
set -u

PROBE=${1:?usage: netprobe.sh ALBI_NETPROBE}
CHECK_HOST=${NETPROBE_CHECK_HOST:-1.1.1.1}
WORK=$(mktemp -d)
fails=0
results=()

[ "$(uname)" = Darwin ] || { echo "macOS only"; exit 2; }
sudo -v || exit 2

pass() { echo "PASS: $*"; results+=("PASS: $*"); }
fail() { echo "FAIL: $*"; results+=("FAIL: $*"); fails=$((fails + 1)); }
note() { echo "NOTE: $*"; results+=("NOTE: $*"); }

# Routes without ARP and cloned host entries, which come and go on their own.
routes() { netstat -rn -f inet | awk 'NR > 4 && $3 !~ /[LWH]/ { print $1, $2, $3, $4 }' | sort; }
default_route() { route -n get default 2>/dev/null | awk '/gateway:|interface:/ { printf "%s ", $2 }'; }
first_resolver() { scutil --dns | awk '/^resolver #1/ { f = 1 } f && /nameserver\[0\]/ { print $3; exit }'; }
resolve() { dscacheutil -q host -a name "$1" | awk '/ip_address:/ { print $2; exit }'; }

PROBE_PID=
cleanup() {
  [ -n "$PROBE_PID" ] && sudo kill -9 "$PROBE_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# scenario NAME full|split term|kill9
scenario() {
  local name=$1 mode=$2 how=$3 log="$WORK/$1.log"
  echo
  echo "== $name: --$mode, stopped by $how"
  local before_routes before_default before_resolver
  before_routes=$(routes)
  before_default=$(default_route)
  before_resolver=$(first_resolver)

  sudo "$PROBE" up "--$mode" --hold 60 --check-host "$CHECK_HOST" >"$log" 2>&1 &
  local i
  for i in $(seq 1 50); do
    grep -q '^READY' "$log" && break
    grep -q '^error' "$log" && break
    sleep 0.2
  done
  if ! grep -q '^READY' "$log"; then
    fail "$name: probe did not come up"
    cat "$log"
    return
  fi
  PROBE_PID=$(sed -n 's/^READY pid=\([0-9]*\).*/\1/p' "$log")
  local utun service
  utun=$(sed -n 's/^READY.* utun=\([^ ]*\).*/\1/p' "$log")
  service=$(sed -n 's/^READY.* service=\([^ ]*\).*/\1/p' "$log")
  sed 's/^/  probe: /' "$log"

  # While up.
  if routes | grep -q " $utun\$"; then pass "$name: routes on $utun"; else fail "$name: no routes on $utun"; fi
  if [ "$mode" = full ]; then
    local r1 got
    r1=$(first_resolver)
    if [ "$r1" = 10.99.0.53 ]; then pass "$name: tunnel DNS is resolver #1"; else fail "$name: resolver #1 is $r1, not the tunnel's"; fi
    got=$(resolve "albi-probe-$name-$RANDOM.example.com")
    if [ "$got" = 192.0.2.53 ]; then pass "$name: lookups go to the tunnel's DNS"; else fail "$name: lookup gave '$got', not the tunnel's answer"; fi
    case "$(sed -n 's/^bound-check=//p' "$log")" in
      connected) pass "$name: socket pinned to the physical interface gets out" ;;
      *) fail "$name: pinned socket: $(sed -n 's/^bound-check=//p' "$log")" ;;
    esac
    case "$(sed -n 's/^unbound-check=//p' "$log")" in
      connected) fail "$name: unpinned socket got out; full-tunnel routes aren't taking traffic" ;;
      *) pass "$name: unpinned socket goes into the tunnel" ;;
    esac
  else
    local got outside
    got=$(resolve "check-$RANDOM.albi-probe.test")
    if [ "$got" = 192.0.2.53 ]; then pass "$name: match-domain lookups go to the tunnel's DNS"; else fail "$name: match-domain lookup gave '$got'"; fi
    if [ "$(first_resolver)" = "$before_resolver" ]; then pass "$name: default resolver unchanged"; else fail "$name: default resolver changed to $(first_resolver)"; fi
    outside=$(resolve "example.com")
    if [ -n "$outside" ] && [ "$outside" != 192.0.2.53 ]; then pass "$name: other names resolve outside"; else note "$name: example.com gave '$outside' (no outside DNS here?)"; fi
  fi

  # Stop, with no cleanup.
  if [ "$how" = kill9 ]; then sudo kill -9 "$PROBE_PID"; else sudo kill -TERM "$PROBE_PID"; fi
  for i in $(seq 1 50); do
    sudo kill -0 "$PROBE_PID" 2>/dev/null || break
    sleep 0.2
  done
  PROBE_PID=
  sleep 2 # configd reacts to the dead session asynchronously

  # After.
  if ifconfig -l | tr ' ' '\n' | grep -qx "$utun"; then fail "$name: $utun still exists"; else pass "$name: $utun is gone"; fi
  local after_routes
  after_routes=$(routes)
  local added
  added=$(comm -13 <(echo "$before_routes") <(echo "$after_routes"))
  if echo "$added" | grep -Eq "$utun|^0/1 |^128.0/1 |^10\.99"; then
    fail "$name: routes left behind:"
    echo "$added" | sed 's/^/    /'
  else
    pass "$name: no tunnel routes left"
  fi
  [ -n "$added" ] && { echo "  other route changes (informational):"; echo "$added" | sed 's/^/    /'; }
  if [ "$(default_route)" = "$before_default" ]; then pass "$name: default route as before"; else fail "$name: default route was '$before_default', now '$(default_route)'"; fi
  if scutil --dns | grep -q 10.99.0.53; then fail "$name: tunnel DNS server still configured"; else pass "$name: tunnel DNS gone"; fi
  if [ "$(first_resolver)" = "$before_resolver" ]; then pass "$name: resolver #1 as before"; else fail "$name: resolver #1 was $before_resolver, now $(first_resolver)"; fi
  if printf 'show State:/Network/Service/%s/DNS\n' "$service" | scutil | grep -q 'No such key'; then
    pass "$name: dynamic-store keys gone"
  else
    fail "$name: State:/Network/Service/$service/DNS still there"
  fi
}

scenario split-term split term
scenario split-kill9 split kill9
scenario full-term full term
scenario full-kill9 full kill9

echo
echo "== summary ($(sw_vers -productVersion), $(uname -m))"
printf '%s\n' "${results[@]}"
[ "$fails" -eq 0 ] && echo "all passed" || echo "$fails failed"
exit $((fails > 0))
