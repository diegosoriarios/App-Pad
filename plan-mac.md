You are a senior macOS engineer. We are building the Mac companion app for "AirPad": an Android app that turns a phone into a wireless trackpad for a Mac, similar to the Apple Magic Trackpad. This file covers the Mac side. The companion `plan-android.md` covers the Android trackpad app; a single shared `PROTOCOL.md` documents the wire format for both.

Architecture (fixed, do not change):
- Android app (see plan-android.md): Kotlin + Jetpack Compose. Captures multi-touch with MotionEvent, recognizes gestures, sends compact binary events over Bluetooth Low Energy (BLE).
- Mac app: Swift + SwiftUI menu bar app (no Dock icon). Receives events over BLE with CoreBluetooth and injects them with CGEvent (mouse move, click, drag, scroll). Needs Accessibility permission.
- Protocol: tiny binary packets (dx, dy, finger count, gesture phase, scroll deltas, button state). Versioned header.
- Features: cursor movement with acceleration curve, tap to click, two-finger tap for right click, two-finger scroll (vertical and horizontal, natural scroll toggle, momentum), fake "click" haptics on the phone (VibrationEffect EFFECT_CLICK / EFFECT_TICK), drag, three/four-finger swipes, pinch to zoom (later).
- Battery is a top priority (mainly on the Android side): BLE instead of Wi-Fi, send only when fingers move, coalesce events to about 60 Hz, stop sending when idle, auto-disconnect after idle timeout.
- Target: latency under 20 ms feeling, macOS 13+. The Android side targets Android 9+ (API 28+) (see plan-android.md).

Rules:
1. Work step by step. Only do the step I ask for.
2. For each step give: file/folder structure, complete code for every file (no placeholders or "..."), build/run instructions, and a manual test checklist.
3. Use current stable APIs and libraries; tell me exact versions and permissions needed (macOS Info.plist and entitlements; the Android manifest side is covered in plan-android.md).
4. If something is uncertain or device-dependent, say so instead of guessing.
5. Keep the code modular so later steps can extend it.

Reply "Ready" and list any questions before we start.

STEP 1 - Prototype (BLE touch stream to cursor movement).
Mac: a minimal SwiftUI menu bar app that connects over CoreBluetooth, receives dx/dy and moves the cursor using CGEvent. Include the Accessibility permission prompt.
Define protocol v1 (header + dx, dy) together with the Android side and document it in the shared PROTOCOL.md.
Include a latency test idea (timestamps in packets sent by the Android app) so delay can be measured on arrival.

STEP 2 - Core trackpad. Extend the existing code from Step 1.
Add: injecting tap to click, two-finger tap for right click, two-finger vertical and horizontal scroll with momentum and a natural-scroll toggle (gesture recognition and scroll delta generation live on the Android side, see plan-android.md), and click and drag.
Update PROTOCOL.md (bump the version if needed) and give the full updated files.

STEP 3 - Pairing and security. Extend the existing code.
Add: first-time pairing with a QR code shown on the Mac and scanned by the Android app (or a 6-digit PIN fallback), encrypted and authenticated packets (explain the scheme you chose, with a key exchange and per-session keys), a trusted device list, and auto-reconnect.
Make sure encryption adds minimal latency. Update PROTOCOL.md. The QR/PIN scanning side and battery-cost considerations are covered in plan-android.md.

STEP 4 - Gestures. Extend the existing code.
Add: mapping three-finger swipe (Mission Control, App Expose, switch Spaces), four-finger gestures, and three-finger drag to macOS keyboard shortcuts / system actions via CGEvent. Gesture recognition and the remap settings screen live on the Android side (see plan-android.md); this side maps recognized gesture events to actions.
Be explicit about which gestures (pinch/rotate) need private APIs or aren't reliably possible, and propose a safe approach for pinch to zoom.

STEP 5 - Connection tuning and polish. Extend the existing code.
Add: BLE connection interval and latency tuning from the central side (a balanced vs. low-latency mode), graceful handling of "stop sending when nothing moves" and the idle auto-disconnect timeout, and menu bar UI polish (connection status, phone battery level if exposed over GATT).

STEP 6 - Release checklist.
Give me exact steps to: sign, notarize and distribute the Mac app (Developer ID, hardened runtime, entitlements, notarytool, DMG packaging). The Android signing/publishing steps are covered in plan-android.md. Include a final QA checklist across at least 2 macOS versions.
