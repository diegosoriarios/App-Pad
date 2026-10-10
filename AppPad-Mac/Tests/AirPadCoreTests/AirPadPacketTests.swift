import XCTest
@testable import AirPadCore

final class AirPadPacketTests: XCTestCase {

    // MARK: - Encoding helpers (mirror PROTOCOL.md v1.1, Little-Endian)

    private func le32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF)
        ]
    }

    private func leFloat(_ value: Float) -> [UInt8] {
        le32(value.bitPattern)
    }

    private func header(type: UInt8) -> [UInt8] {
        [AirPadPacket.protocolVersion, type]
    }

    private func pad(_ bytes: [UInt8]) -> Data {
        var result = bytes
        precondition(result.count <= AirPadPacket.length)
        result.append(contentsOf: repeatElement(0, count: AirPadPacket.length - result.count))
        return Data(result)
    }

    private func makeMove(fingerCount: UInt8 = 1, timestamp: UInt32 = 1234, dx: Float, dy: Float) -> Data {
        pad(header(type: 0x01) + [fingerCount] + le32(timestamp) + leFloat(dx) + leFloat(dy))
    }

    private func makeClick(button: UInt8, phase: UInt8, timestamp: UInt32 = 42) -> Data {
        pad(header(type: 0x02) + [button, phase] + le32(timestamp))
    }

    private func makeScroll(fingerCount: UInt8 = 2, timestamp: UInt32 = 99, dx: Float, dy: Float) -> Data {
        pad(header(type: 0x03) + [fingerCount] + le32(timestamp) + leFloat(dx) + leFloat(dy))
    }

    private func makeGesture(action: UInt8, origin: UInt8, direction: UInt8, timestamp: UInt32 = 777) -> Data {
        pad(header(type: 0x04) + [action, origin, direction] + le32(timestamp))
    }

    // MARK: - Tests

    func testParsesMovePacket() throws {
        let packet = try XCTUnwrap(AirPadPacket.parse(makeMove(dx: 3.5, dy: -7.25)))
        XCTAssertEqual(packet.type, .move)
        XCTAssertEqual(packet.timestampMs, 1234)
        XCTAssertEqual(packet.payload, .move(fingerCount: 1, dx: 3.5, dy: -7.25))
    }

    func testParsesClickPacket() throws {
        let packet = try XCTUnwrap(AirPadPacket.parse(makeClick(button: 0x01, phase: 0x00)))
        XCTAssertEqual(packet.type, .click)
        XCTAssertEqual(packet.timestampMs, 42)
        XCTAssertEqual(packet.payload, .click(button: .right, phase: .press))
    }

    func testParsesScrollPacket() throws {
        let packet = try XCTUnwrap(AirPadPacket.parse(makeScroll(dx: -12.0, dy: 8.5)))
        XCTAssertEqual(packet.type, .scroll)
        XCTAssertEqual(packet.timestampMs, 99)
        XCTAssertEqual(packet.payload, .scroll(fingerCount: 2, dx: -12.0, dy: 8.5))
    }

    func testRejectsWrongLength() {
        XCTAssertNil(AirPadPacket.parse(Data(repeating: 0, count: 14)))
        XCTAssertNil(AirPadPacket.parse(Data(repeating: 0, count: 16)))
        XCTAssertNil(AirPadPacket.parse(Data()))
    }

    func testRejectsWrongVersion() {
        var data = makeMove(dx: 1, dy: 1)
        data[0] = 0x02
        XCTAssertNil(AirPadPacket.parse(data))
    }

    func testIgnoresUnknownPacketType() {
        // Forward compatibility: unknown types must be dropped, not crash
        var data = makeMove(dx: 1, dy: 1)
        data[1] = 0x7F
        XCTAssertNil(AirPadPacket.parse(data))
    }

    func testRejectsInvalidClickValues() {
        XCTAssertNil(AirPadPacket.parse(makeClick(button: 0x05, phase: 0x00)))
        XCTAssertNil(AirPadPacket.parse(makeClick(button: 0x00, phase: 0x09)))
    }

    // MARK: - Gesture events (PROTOCOL.md §8)

    func testParsesGesturePacket() throws {
        let packet = try XCTUnwrap(AirPadPacket.parse(
            makeGesture(action: GestureAction.missionControl.rawValue,
                        origin: GestureOrigin.threeFingerSwipe.rawValue,
                        direction: GestureDirection.up.rawValue)
        ))
        XCTAssertEqual(packet.type, .gesture)
        XCTAssertEqual(packet.timestampMs, 777)
        XCTAssertEqual(packet.payload, .gesture(actionCode: 0x01, origin: 0x01, direction: 0x00))
    }

    func testGesturePacketPassesUnknownActionThrough() throws {
        // Forward compatibility: the parser must not drop unknown action
        // codes — the mapper decides what to do with them.
        let packet = try XCTUnwrap(AirPadPacket.parse(makeGesture(action: 0xAB, origin: 0x02, direction: 0x03)))
        XCTAssertEqual(packet.payload, .gesture(actionCode: 0xAB, origin: 0x02, direction: 0x03))
    }
}
