import Foundation
import CoreGraphics

/// Semantic actions a recognized gesture can trigger on the Mac.
/// Wire codes are stable and must match the Android `GestureAction` catalog
/// (PROTOCOL.md §8 action catalog).
public enum GestureAction: UInt8 {
    /// Never sent over the wire (slot disabled sender-side).
    case disabled = 0x00
    case missionControl = 0x01
    case appExpose = 0x02
    /// One Space to the right — triggered by a physical swipe left.
    case spaceNext = 0x03
    /// One Space to the left — triggered by a physical swipe right.
    case spacePrev = 0x04
    case showDesktop = 0x05
    case launchpad = 0x06
    case notificationCenter = 0x07
}

/// Raw gesture that produced an action (diagnostics/logging).
public enum GestureOrigin: UInt8 {
    case threeFingerSwipe = 0x01
    case fourFingerSwipe = 0x02
}

/// Physical finger-travel direction carried in gesture packets.
public enum GestureDirection: UInt8 {
    case up = 0x00
    case down = 0x01
    case left = 0x02
    case right = 0x03
}

extension GestureAction {
    /// Human-readable name for the menu bar / logs.
    public var displayName: String {
        switch self {
        case .disabled: return "Disabled"
        case .missionControl: return "Mission Control"
        case .appExpose: return "App Expose"
        case .spaceNext: return "Next Space"
        case .spacePrev: return "Previous Space"
        case .showDesktop: return "Show Desktop"
        case .launchpad: return "Launchpad"
        case .notificationCenter: return "Notification Center"
        }
    }
}

/// Maps actions to synthetic keyboard shortcuts.
///
/// Only public CGEvent keyboard injection is used — the private gesture
/// event routes (kCGEventGesture / IOHIDPostEvent) are intentionally avoided.
/// Keycodes are the Carbon HIToolbox kVK_* values.
public enum GestureActionMapping {

    public struct Shortcut: Equatable {
        public let keyCode: UInt64
        public let flags: CGEventFlags

        public init(keyCode: UInt64, flags: CGEventFlags) {
            self.keyCode = keyCode
            self.flags = flags
        }
    }

    private enum VirtualKey {
        /// kVK_F4
        static let f4: UInt64 = 0x76
        /// kVK_F11
        static let f11: UInt64 = 0x67
        /// kVK_LeftArrow
        static let leftArrow: UInt64 = 0x7B
        /// kVK_RightArrow
        static let rightArrow: UInt64 = 0x7C
        /// kVK_DownArrow
        static let downArrow: UInt64 = 0x7D
        /// kVK_UpArrow
        static let upArrow: UInt64 = 0x7E
    }

    /// Returns the default shortcut for an action, or nil when the action
    /// has no reliable public shortcut (Notification Center) or is disabled.
    public static func shortcut(for action: GestureAction) -> Shortcut? {
        switch action {
        case .missionControl:
            return Shortcut(keyCode: VirtualKey.upArrow, flags: .maskControl)
        case .appExpose:
            return Shortcut(keyCode: VirtualKey.downArrow, flags: .maskControl)
        case .spaceNext:
            return Shortcut(keyCode: VirtualKey.rightArrow, flags: .maskControl)
        case .spacePrev:
            return Shortcut(keyCode: VirtualKey.leftArrow, flags: .maskControl)
        case .showDesktop:
            // fn+F11: Show Desktop with default function-key settings; plain
            // F11 when "use F1/F2 as standard function keys" is enabled.
            return Shortcut(keyCode: VirtualKey.f11, flags: .maskSecondaryFn)
        case .launchpad:
            return Shortcut(keyCode: VirtualKey.f4, flags: .maskSecondaryFn)
        case .notificationCenter, .disabled:
            // No public global shortcut for Notification Center.
            return nil
        }
    }
}
