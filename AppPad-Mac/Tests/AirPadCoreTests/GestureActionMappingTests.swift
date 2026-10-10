import XCTest
@testable import AirPadCore

final class GestureActionMappingTests: XCTestCase {

    // MARK: - Wire-code stability (must match the Android catalog, PROTOCOL.md §8)

    func testActionCodesAreStable() {
        XCTAssertEqual(GestureAction.disabled.rawValue, 0x00)
        XCTAssertEqual(GestureAction.missionControl.rawValue, 0x01)
        XCTAssertEqual(GestureAction.appExpose.rawValue, 0x02)
        XCTAssertEqual(GestureAction.spaceNext.rawValue, 0x03)
        XCTAssertEqual(GestureAction.spacePrev.rawValue, 0x04)
        XCTAssertEqual(GestureAction.showDesktop.rawValue, 0x05)
        XCTAssertEqual(GestureAction.launchpad.rawValue, 0x06)
        XCTAssertEqual(GestureAction.notificationCenter.rawValue, 0x07)
    }

    func testOriginAndDirectionCodesAreStable() {
        XCTAssertEqual(GestureOrigin.threeFingerSwipe.rawValue, 0x01)
        XCTAssertEqual(GestureOrigin.fourFingerSwipe.rawValue, 0x02)
        XCTAssertEqual(GestureDirection.up.rawValue, 0)
        XCTAssertEqual(GestureDirection.down.rawValue, 1)
        XCTAssertEqual(GestureDirection.left.rawValue, 2)
        XCTAssertEqual(GestureDirection.right.rawValue, 3)
    }

    // MARK: - Default shortcut mapping

    func testCoreActionsMapToControlArrows() {
        // kVK_UpArrow = 0x7E, Down = 0x7D, Left = 0x7B, Right = 0x7C
        XCTAssertEqual(
            GestureActionMapping.shortcut(for: .missionControl),
            GestureActionMapping.Shortcut(keyCode: 0x7E, flags: .maskControl)
        )
        XCTAssertEqual(
            GestureActionMapping.shortcut(for: .appExpose),
            GestureActionMapping.Shortcut(keyCode: 0x7D, flags: .maskControl)
        )
        XCTAssertEqual(
            GestureActionMapping.shortcut(for: .spaceNext),
            GestureActionMapping.Shortcut(keyCode: 0x7C, flags: .maskControl)
        )
        XCTAssertEqual(
            GestureActionMapping.shortcut(for: .spacePrev),
            GestureActionMapping.Shortcut(keyCode: 0x7B, flags: .maskControl)
        )
    }

    func testFunctionKeyActionsCarryTheFnFlag() {
        // kVK_F11 = 0x67, kVK_F4 = 0x76
        let showDesktop = GestureActionMapping.shortcut(for: .showDesktop)
        XCTAssertEqual(showDesktop?.keyCode, 0x67)
        XCTAssertTrue(showDesktop!.flags.contains(.maskSecondaryFn))

        let launchpad = GestureActionMapping.shortcut(for: .launchpad)
        XCTAssertEqual(launchpad?.keyCode, 0x76)
        XCTAssertTrue(launchpad!.flags.contains(.maskSecondaryFn))
    }

    func testActionsWithoutPublicShortcutsMapToNil() {
        XCTAssertNil(GestureActionMapping.shortcut(for: .notificationCenter))
        XCTAssertNil(GestureActionMapping.shortcut(for: .disabled))
    }

    func testUnknownRawCodeDoesNotProduceAnAction() {
        XCTAssertNil(GestureAction(rawValue: 0xAB))
        XCTAssertNotNil(GestureAction(rawValue: 0x07))
    }
}
