#!/bin/bash
# Does SMAppService register a LaunchDaemon from an app signed without a
# paid Apple Developer team? Builds a tiny AlbiProbe.app around
# albi-netprobe, signs it, registers its daemon, asks you to approve it in
# System Settings if macOS wants that, checks the daemon ran as root, then
# unregisters it.
#
#   scripts/smappservice-probe.sh /path/to/albi-netprobe [IDENTITY]
#
# IDENTITY is a codesign identity: "-" (ad-hoc, the default) or
# "Apple Development" (the free certificate Xcode makes for a personal team).
# Run it once with each. Paste the summary at the end back into the thread.
set -u

BIN=${1:?usage: smappservice-probe.sh ALBI_NETPROBE [IDENTITY]}
IDENTITY=${2:--}
# PROBE_ID gives the daemon a fresh label and bundle id, so launchd keeps no
# code requirement from an earlier registration signed another way.
ID=${PROBE_ID:-com.github.njvack.albi.probe}
PLIST=$ID.plist
WORK=$(mktemp -d)
APP="$WORK/AlbiProbe.app"
MARK=/var/tmp/albi-netprobe-daemon.txt

[ "$(uname)" = Darwin ] || { echo "macOS only"; exit 2; }

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Library/LaunchDaemons"
cp "$BIN" "$APP/Contents/MacOS/albi-netprobe"
cat >"$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$ID</string>
  <key>CFBundleExecutable</key><string>albi-netprobe</string>
  <key>CFBundleName</key><string>AlbiProbe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.0.1</string>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF
cat >"$APP/Contents/Library/LaunchDaemons/$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$ID</string>
  <key>BundleProgram</key><string>Contents/MacOS/albi-netprobe</string>
  <key>ProgramArguments</key><array><string>albi-netprobe</string><string>daemon-mark</string></array>
  <key>RunAtLoad</key><true/>
  <key>AssociatedBundleIdentifiers</key><array><string>$ID</string></array>
</dict></plist>
EOF

echo "== signing with '$IDENTITY'"
if ! codesign --force --options runtime --timestamp=none --sign "$IDENTITY" "$APP"; then
  echo "codesign failed"; exit 1
fi
codesign -dvv "$APP" 2>&1 | grep -E 'Signature|Authority|TeamIdentifier' | sed 's/^/  /'

sudo rm -f "$MARK"
run() { "$APP/Contents/MacOS/albi-netprobe" sm "$1" "$PLIST"; }

echo "== register"
reg=$(run register); echo "$reg"
if echo "$reg" | grep -q 'status: requiresApproval'; then
  echo "macOS wants approval: System Settings > General > Login Items & Extensions, turn on AlbiProbe."
  open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension" 2>/dev/null
  read -r -p "Press return once it's on (or if it never shows up)... " _
  run status
fi
sleep 3
echo "== launchd"
sudo launchctl print "system/$ID" 2>&1 | grep -E 'state|program|last exit|LWCR' | sed 's/^/  /'
echo "== daemon mark"
if [ -f "$MARK" ]; then ran="yes: $(cat "$MARK")"; else ran="no"; fi
echo "  $ran"
echo "== unregister"
run unregister
rm -rf "$WORK"

echo
echo "== summary ($(sw_vers -productVersion), signed '$IDENTITY')"
echo "$reg" | sed 's/^/  /'
echo "  daemon ran: $ran"
