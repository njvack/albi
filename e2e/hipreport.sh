#!/bin/bash
# End-to-end: real openconnect (kept as a reference client) runs hipreport as its --csd-wrapper against
# the fake GlobalProtect gateway (github.com/njvack/gp-fake-gateway), and we
# check what the gateway received. Linux, root (openconnect needs a tun).
#
#   sudo e2e/hipreport.sh OPENCONNECT FAKEGP HIPREPORT VPNC_SCRIPT
#
# hipreport replays Tests/HIPCoreTests/Fixtures/mac-basic.toml, so the report is a Mac's even
# on Linux. Only the fake's test subnet is routed; nothing else is touched.
set -u

OC=${1:?usage: hipreport.sh OPENCONNECT FAKEGP HIPREPORT VPNC_SCRIPT}
FAKEGP=${2:?}
HIPREPORT=${3:?}
VPNC=${4:?}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
chmod 755 "$WORK"
LISTEN=127.0.0.1:18443
CONTROL=127.0.0.1:18444
DEV=hipe2e
fails=0

unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

cleanup() {
  pkill -f -- "--interface=$DEV" 2>/dev/null
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

# openconnect execs the wrapper with a fixed argv, so a shim adds ours.
cp "$HIPREPORT" "$WORK/hipreport"
# The built-in check library is a resource bundle next to the binary.
cp -R "$(dirname "$HIPREPORT")/Albi_HIPCore.resources" "$WORK/"
chmod -R a+rX "$WORK/Albi_HIPCore.resources"
cp "$HERE/../Tests/HIPCoreTests/Fixtures/mac-basic.toml" "$WORK/mac.toml"
cat >"$WORK/wrapper" <<SH
#!/bin/sh
echo "\$@" >"$WORK/out/argv"
exec "$WORK/hipreport" --fixture "$WORK/mac.toml" --checks-dir /nonexistent "\$@"
SH
chmod 755 "$WORK/wrapper" "$WORK/hipreport"
chmod 644 "$WORK/mac.toml"
mkdir -m 1777 "$WORK/out"

"$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
GP_PID=$!
wait_for 10 test -s "$WORK/pin" || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
ctl PUT /config '{"hip_needed": true}' >/dev/null

# --csd-user drops privileges for the wrapper, as a real setup would. It
# needs a user with a home directory (nobody's is /nonexistent on Ubuntu).
id hipreport-e2e >/dev/null 2>&1 || useradd --create-home hipreport-e2e
printf 'test\n1\n' | "$OC" --protocol=gp --servercert="$(cat "$WORK/pin")" -u test \
  --script="$VPNC" --interface="$DEV" --csd-user=hipreport-e2e --csd-wrapper="$WORK/wrapper" \
  "$LISTEN" >"$WORK/oc.log" 2>&1 &

reports() {
  ctl GET /sessions | python3 -c 'import json, sys; print(json.dumps([r for s in json.load(sys.stdin) for r in (s["hip_reports"] or [])]))'
}
got_report() { [ "$(reports)" != "[]" ]; }

if wait_for 20 got_report; then pass "gateway received a HIP report"; else fail "no HIP report reached the gateway"; fi

reports | ARGV="$(cat "$WORK/out/argv" 2>/dev/null)" python3 -c '
import json, os, sys, xml.etree.ElementTree as ET
reps = json.load(sys.stdin)
if not reps:
    sys.exit(1)
r = reps[-1]
root = ET.fromstring(r["report"])
def check(cond, msg):
    print(("PASS: " if cond else "FAIL: ") + msg)
    return cond
ok = True
argv = os.environ["ARGV"].split()
want = argv[argv.index("--md5") + 1] if "--md5" in argv else None
ok &= check(want and root.findtext("md5-sum") == want, "md5-sum is the --md5 openconnect passed (%s)" % want)
ok &= check(root.findtext("user-name") == "test", "user-name comes from the login cookie")
ok &= check(root.findtext("ip-address") == "10.99.0.2", "ip-address is the address the gateway assigned")
names = [p.get("name") for p in root.iter("Prod")]
ok &= check("Xprotect" in names and "FileVault" in names, "Apple products from the built-in library are listed")
cats = [e.get("name") for e in root.find("categories")]
ok &= check(cats == ["host-info", "anti-malware", "disk-backup", "disk-encryption", "firewall", "patch-management", "data-loss-prevention"], "categories in GP order")
sys.exit(0 if ok else 1)
' || fails=$((fails + 1))

if grep -q 'HIP report submitted successfully' "$WORK/oc.log"; then pass "openconnect says the report was accepted"; else fail "openconnect did not report success"; fi
if grep -q -- '--md5' "$WORK/out/argv" 2>/dev/null; then pass "wrapper got openconnect's arguments"; else fail "wrapper argv: $(cat "$WORK/out/argv" 2>/dev/null)"; fi

if [ "$fails" -ne 0 ]; then
  echo "--- fakegp log"; tail -40 "$WORK/fakegp.log"
  echo "--- openconnect log"; tail -40 "$WORK/oc.log"
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
