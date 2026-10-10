import Foundation
import CoreGraphics
import ApplicationServices
import AppKit
import AirPadCore

/// Injects AirPad input into macOS via CGEvent.
///
/// Requires Accessibility permission (System Settings → Privacy & Security →
/// Accessibility). Movement is posted as .mouseMoved, or as .leftMouseDragged
/// / .rightMouseDragged while the corresponding logical button is held, so
/// click-and-drag sequences from the phone work natively.
///
/// Scroll deltas arrive in finger-travel direction with natural scrolling
/// already applied sender-side (PROTOCOL.md v1.1). CGEvent wheel values are
/// positive = scroll up / content moves down, so the incoming deltas are
/// negated: contentShift = -incoming. Deltas are accumulated and truncated
/// toward zero so sub-pixel packets at 60 Hz are not lost.
final class CursorInjector: ObservableObject {
    @Published var isAccessibilityGranted: Bool = false

    private var scrollAccumulatorX: Double = 0
    private var scrollAccumulatorY: Double = 0

    private var isLeftButtonDown = false
    private var isRightButtonDown = false

    init() {
        checkAccessibilityPermissions()
    }

    // MARK: - Accessibility

    func checkAccessibilityPermissions() {
        let trusted = AXIsProcessTrusted()
        DispatchQueue.main.async {
            self.isAccessibilityGranted = trusted
        }
    }

    func requestAccessibilityPermissions() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        let trusted = AXIsProcessTrustedWithOptions(options)
        DispatchQueue.main.async {
            self.isAccessibilityGranted = trusted
        }
    }

    // MARK: - Input injection

    func moveCursor(dx: Float, dy: Float) {
        guard isAccessibilityGranted else { return }

        let currentMouseLocation = CGEvent(source: nil)?.location ?? CGPoint.zero
        let newLocation = CGPoint(
            x: currentMouseLocation.x + CGFloat(dx),
            y: currentMouseLocation.y + CGFloat(dy)
        )

        let type: CGEventType
        let button: CGMouseButton
        if isLeftButtonDown {
            type = .leftMouseDragged
            button = .left
        } else if isRightButtonDown {
            type = .rightMouseDragged
            button = .right
        } else {
            type = .mouseMoved
            button = .left
        }

        postMouseEvent(type: type, location: newLocation, button: button)
    }

    func click(button: AirPadPacket.Button, phase: AirPadPacket.Phase) {
        guard isAccessibilityGranted else { return }

        let down = phase == .press
        switch button {
        case .left:
            isLeftButtonDown = down
        case .right:
            isRightButtonDown = down
        }

        let location = CGEvent(source: nil)?.location ?? CGPoint.zero
        let type: CGEventType
        switch (button, down) {
        case (.left, true): type = .leftMouseDown
        case (.left, false): type = .leftMouseUp
        case (.right, true): type = .rightMouseDown
        case (.right, false): type = .rightMouseUp
        }

        postMouseEvent(type: type, location: location, button: button == .left ? .left : .right)
    }

    func scroll(dx: Float, dy: Float) {
        guard isAccessibilityGranted else { return }

        scrollAccumulatorX += Double(dx)
        scrollAccumulatorY += Double(dy)

        // Convert accumulated pixel deltas to integer wheel ticks, keeping
        // the fractional remainder for the next packet.
        let wheel1Double = -scrollAccumulatorY
        let wheel2Double = -scrollAccumulatorX
        let wheel1 = Int32(wheel1Double.rounded(.towardZero))
        let wheel2 = Int32(wheel2Double.rounded(.towardZero))
        scrollAccumulatorY += Double(wheel1)
        scrollAccumulatorX += Double(wheel2)

        guard wheel1 != 0 || wheel2 != 0 else { return }

        let event = CGEvent(
            scrollWheelEvent2Source: nil,
            units: .pixel,
            wheelCount: 2,
            wheel1: wheel1,
            wheel2: wheel2,
            wheel3: 0
        )
        event?.post(tap: .cghidEventTap)
    }

    /// Injects the keyboard shortcut bound to a gesture action
    /// (PROTOCOL.md §8). Unknown action codes and unmapped actions are
    /// ignored.
    /// Injects the keyboard shortcut bound to a gesture action
    /// (PROTOCOL.md §8). Unknown action codes and unmapped actions are
    /// ignored.
    ///
    /// macOS filters synthetic modifier+key chords out of SYSTEM hotkey
    /// handling (Mission Control, Spaces), so those four actions go through
    /// osascript, which inherits this app's Accessibility grant. Plain key
    /// taps (fn+F11/F4) stay synthetic.
    func gestureAction(rawCode: UInt8) {
        guard isAccessibilityGranted else { return }
        guard let action = GestureAction(rawValue: rawCode), action != .disabled else { return }
        switch action {
        case .missionControl:
            osascriptKey(keyCode: 126, modifiers: "control down") // up arrow
        case .appExpose:
            osascriptKey(keyCode: 125, modifiers: "control down") // down arrow
        case .spaceNext:
            osascriptKey(keyCode: 124, modifiers: "control down") // right arrow
        case .spacePrev:
            osascriptKey(keyCode: 123, modifiers: "control down") // left arrow
        case .launchpad:
            let p = Process()
            p.launchPath = "/usr/bin/open"
            p.arguments = ["-a", "Launchpad"]
            try? p.run()
        default:
            guard let shortcut = GestureActionMapping.shortcut(for: action) else { return }
            postKeyTap(keyCode: shortcut.keyCode, flags: shortcut.flags)
        }
    }

    /// Runs `osascript` to inject a system-level key chord. Attribution of
    /// the child process resolves to this app (Accessibility granted).
    private func osascriptKey(keyCode: Int, modifiers: String) {
        let p = Process()
        p.launchPath = "/usr/bin/osascript"
        p.arguments = ["-e", "tell application \"System Events\" to key code \(keyCode) using {\(modifiers)}"]
        try? p.run()
    }

    /// Clears held buttons / scroll inertia state (e.g. on disconnect).
    func resetState() {
        if isLeftButtonDown {
            click(button: .left, phase: .release)
        }
        if isRightButtonDown {
            click(button: .right, phase: .release)
        }
        scrollAccumulatorX = 0
        scrollAccumulatorY = 0
    }

    // MARK: - Private

    private func postMouseEvent(type: CGEventType, location: CGPoint, button: CGMouseButton) {
        guard let event = CGEvent(
            mouseEventSource: nil,
            mouseType: type,
            mouseCursorPosition: location,
            mouseButton: button
        ) else { return }
        event.post(tap: .cghidEventTap)
    }

    private func postKeyTap(keyCode: UInt64, flags: CGEventFlags) {
        let key = CGKeyCode(truncatingIfNeeded: keyCode)
        // combinedSessionState merges real hardware state with posted events;
        // .hidSystemState events get filtered out by system-level hotkey
        // handling (Mission Control, Spaces).
        let source = CGEventSource(stateID: .combinedSessionState)
        guard let down = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: true),
              let up = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: false) else { return }

        // Press/release the modifiers as real events around the key: system
        // hotkeys watch the modifier state sequence, not just event flags.
        let modifierKeyCodes: [(CGKeyCode, CGEventFlags)] = [
            (0x3B, .maskControl),   // left control
            (0x3A, .maskAlternate), // left option
            (0x38, .maskShift),     // left shift
            (0x37, .maskCommand),   // left command
            (0x3D, .maskSecondaryFn) // fn
        ]
        for (modKey, mask) in modifierKeyCodes where flags.contains(mask) {
            if let modDown = CGEvent(keyboardEventSource: source, virtualKey: modKey, keyDown: true) {
                modDown.flags = flags
                modDown.post(tap: .cgSessionEventTap)
            }
            usleep(10_000)
        }

        down.flags = flags
        down.post(tap: .cgSessionEventTap)
        // Give the system a beat between down and up so chords register.
        usleep(30_000)
        up.flags = flags
        up.post(tap: .cgSessionEventTap)
        usleep(10_000)

        for (modKey, mask) in modifierKeyCodes.reversed() where flags.contains(mask) {
            if let modUp = CGEvent(keyboardEventSource: source, virtualKey: modKey, keyDown: false) {
                modUp.flags = []
                modUp.post(tap: .cgSessionEventTap)
            }
            usleep(10_000)
        }
    }
}
