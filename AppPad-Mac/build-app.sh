#!/bin/bash
# Builds AppPad-Mac and assembles dist/AppPad.app (menu bar app bundle).
#
# The bundle is required for macOS privacy (TCC): CoreBluetooth needs
# NSBluetoothAlwaysUsageDescription from the running process's Info.plist —
# a bare `swift run` executable has none and gets killed on launch.
#
# Usage: ./build-app.sh [--release]
set -euo pipefail
cd "$(dirname "$0")"

CONFIG=debug
if [ "${1:-}" = "--release" ]; then CONFIG=release; fi

swift build -c "$CONFIG"

APP="dist/AppPad.app"
CONTENTS="$APP/Contents"

rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS"
cp ".build/$CONFIG/AppPad-Mac" "$CONTENTS/MacOS/AppPad-Mac"
cp Info.plist "$CONTENTS/Info.plist"
printf 'APPL????' > "$CONTENTS/PkgInfo"

# Signing: use the stable "AppPad Dev" self-signed identity when present so
# TCC grants (Bluetooth, Accessibility) survive rebuilds; fall back to ad-hoc
# (grants then go stale on every rebuild). Step 6 replaces this with a
# Developer ID signature.
IDENTITY="AppPad Dev"
if ! security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
    IDENTITY="-"
    echo "warning: 'AppPad Dev' identity not found — signing ad-hoc (TCC grants won't persist)"
fi
codesign --force -s "$IDENTITY" --entitlements AppPad-Mac.entitlements "$APP"

echo
echo "Built $APP"
echo "Run:  open $APP"
