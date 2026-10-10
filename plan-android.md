You are a senior mobile engineer. We are building "AirPad": an Android app that turns a phone into a wireless trackpad for a Mac, similar to the Apple Magic Trackpad. This file covers the Android side. The companion `plan-mac.md` covers the Mac receiver app; a single shared `PROTOCOL.md` documents the wire format for both.

Architecture (fixed, do not change):
- Android app: Kotlin + Jetpack Compose. Captures multi-touch with MotionEvent, recognizes gestures, sends compact binary events over Bluetooth Low Energy (BLE) as a GATT peripheral/central (propose the best role split and justify it briefly).
- Mac app (see plan-mac.md): Swift + SwiftUI menu bar app (no Dock icon). Receives events over BLE with CoreBluetooth and injects them with CGEvent (mouse move, click, drag, scroll). Needs Accessibility permission.
- Protocol: tiny binary packets (dx, dy, finger count, gesture phase, scroll deltas, button state). Versioned header.
- Features: cursor movement with acceleration curve, tap to click, two-finger tap for right click, two-finger scroll (vertical and horizontal, natural scroll toggle, momentum), fake "click" haptics using VibrationEffect (EFFECT_CLICK / EFFECT_TICK) with intensity setting, drag, three/four-finger swipes, pinch to zoom (later).
- Battery is a top priority: BLE instead of Wi-Fi, send only when fingers move, coalesce events to about 60 Hz, stop sending when idle, wake locks only during active sessions, near-black OLED-friendly UI, auto-disconnect after idle timeout.
- Target: latency under 20 ms feeling, Android 9+ (API 28+). The Mac side targets macOS 13+ (see plan-mac.md).

Rules:
1. Work step by step. Only do the step I ask for.
2. For each step give: file/folder structure, complete code for every file (no placeholders or "..."), build/run instructions, and a manual test checklist.
3. Use current stable APIs and libraries; tell me exact versions and permissions needed (Android manifest; the macOS Info.plist/entitlements side is covered in plan-mac.md).
4. If something is uncertain or device-dependent, say so instead of guessing.
5. Keep the code modular so later steps can extend it.

Reply "Ready" and list any questions before we start.

STEP 1 - Prototype (BLE touch stream to cursor movement).
Android: a Compose screen with a full-screen touch area. One-finger movement sends relative dx/dy over BLE. Include runtime Bluetooth permissions for Android 12+ and older versions.
Define protocol v1 (header + dx, dy) together with the Mac side and document it in the shared PROTOCOL.md.
Include a latency test idea (timestamps in packets) so delay can be measured end to end; the Mac side measures arrival time (see plan-mac.md).

STEP 2 - Core trackpad. Extend the existing code from Step 1.
Add: tap to click, two-finger tap for right click, two-finger vertical and horizontal scroll with momentum and a natural-scroll toggle (scroll deltas are sent over BLE; the Mac app injects the actual scroll events, see plan-mac.md), pointer acceleration curve, click and drag, and haptic feedback (EFFECT_CLICK on press, EFFECT_TICK on release, intensity setting, fallback to performHapticFeedback).
Show the gesture recognizer as a state machine with time and distance thresholds as named constants.
Update PROTOCOL.md (bump the version if needed) and give the full updated files.

STEP 3 - Pairing and security. Extend the existing code.
Add: first-time pairing by scanning the QR code shown on the Mac (or a 6-digit PIN fallback), encrypted and authenticated packets (explain the scheme you chose, with a key exchange and per-session keys), a trusted device list, and auto-reconnect.
Make sure encryption adds minimal latency and battery cost. Update PROTOCOL.md. The QR/PIN display and key-exchange host side are covered in plan-mac.md.

STEP 4 - Gestures. Extend the existing code.
Add: recognition of three-finger swipe (Mission Control, App Expose, switch Spaces — mapped to macOS shortcuts by the Mac app, see plan-mac.md), four-finger gestures, three-finger drag, and a settings screen on Android to enable, disable and remap gestures.
Be explicit about which gestures (pinch/rotate) need private APIs or aren't reliably possible, and propose a safe approach for pinch to zoom.

STEP 5 - Battery tuning and polish. Extend the existing code.
Add: event coalescing at about 60 Hz with an idle rate drop, stop sending when nothing moves, BLE connection interval and latency tuning (a balanced vs. low-latency mode), a foreground service only while connected, an idle auto-disconnect timeout, a near-black "trackpad only" mode with the screen dimmed, and an onboarding flow.
Give me a battery test plan using Android Battery Historian and Perfetto, and list what to measure.

STEP 6 - Release checklist.
Give me exact steps to: sign and publish the Android app on GitHub, generate a .github action and update the apk to release, and generate the keystore (privacy policy, permissions declarations, data safety form). The Mac signing/notarization steps are covered in plan-mac.md. Include a final QA checklist across at least 3 Android devices.
