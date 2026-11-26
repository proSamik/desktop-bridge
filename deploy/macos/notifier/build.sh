#!/bin/sh
# Build and install "Desktop Bridge.app" (clickable notifications for desktop-bridge on macOS).
# Needs Xcode or the Command Line Tools (swiftc). Usage: deploy/macos/notifier/build.sh [install dir, default ~/Applications]
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/Applications}"
APP="$DEST/Desktop Bridge.app"
TMP="$(mktemp -d)"
mkdir -p "$TMP/Desktop Bridge.app/Contents/MacOS"
cp "$SRC/Info.plist" "$TMP/Desktop Bridge.app/Contents/Info.plist"
swiftc -O -o "$TMP/Desktop Bridge.app/Contents/MacOS/notifier" "$SRC/main.swift" -framework Cocoa -framework UserNotifications
codesign --force --sign - "$TMP/Desktop Bridge.app"           # ad-hoc signature (local use)
mkdir -p "$DEST" && rm -rf "$APP" && mv "$TMP/Desktop Bridge.app" "$APP" && rm -rf "$TMP"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" 2>/dev/null || true
echo "installed $APP"
open "$APP"      # first launch asks macOS for notification permission: click "Allow"
echo "If no permission prompt appears: System Settings > Notifications > Desktop Bridge > Allow Notifications."
