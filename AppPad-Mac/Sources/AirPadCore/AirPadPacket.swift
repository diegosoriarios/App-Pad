import Foundation

/// Parser for the AirPad BLE wire protocol (PROTOCOL.md v2).
///
/// Every packet is exactly 15 bytes, Little-Endian:
///  - byte 0: protocol version (`0x01`)
///  - byte 1: packet type (`0x01` move, `0x02` click, `0x03` scroll,
///    `0x04` gesture event)
///  - move / scroll: byte 2 finger count, bytes 3-6 timestamp ms,
///    bytes 7-10 dx (float32), bytes 11-14 dy (float32)
///  - click: byte 2 button, byte 3 phase, bytes 3-6 timestamp, rest reserved
///  - gesture: byte 2 action code, byte 3 origin gesture, byte 4 direction,
///    bytes 5-8 timestamp, rest reserved
///
/// Parsing is done byte-by-byte to avoid unaligned memory loads (the float
/// fields sit at offsets 7 and 11, which are not 4-byte aligned).
public enum AirPadPacket {
    public static let length = 15
    public static let protocolVersion: UInt8 = 0x01

    public enum PacketType: UInt8 {
        case move = 0x01
        case click = 0x02
        case scroll = 0x03
        case gesture = 0x04
    }

    public enum Button: UInt8 {
        case left = 0x00
        case right = 0x01
    }

    public enum Phase: UInt8 {
        case press = 0x00
        case release = 0x01
    }

    public enum Payload: Equatable {
        case move(fingerCount: UInt8, dx: Float, dy: Float)
        case click(button: Button, phase: Phase)
        case scroll(fingerCount: UInt8, dx: Float, dy: Float)
        /// Semantic action + raw origin/direction codes (PROTOCOL.md §8).
        /// Unknown action codes pass through; the mapper decides whether to
        /// act (forward compatibility).
        case gesture(actionCode: UInt8, origin: UInt8, direction: UInt8)
    }

    public struct Packet: Equatable {
        public let type: PacketType
        public let timestampMs: UInt32
        public let payload: Payload
    }

    /// Parses one notification payload. Returns nil for wrong length, wrong
    /// protocol version, or unknown packet types (which v1.1 clients must
    /// ignore for forward compatibility).
    public static func parse(_ data: Data) -> Packet? {
        guard data.count == length else { return nil }
        let bytes = [UInt8](data)

        guard bytes[0] == protocolVersion else { return nil }
        guard let type = PacketType(rawValue: bytes[1]) else { return nil }

        switch type {
        case .move:
            return Packet(
                type: .move,
                timestampMs: Self.readUInt32LE(bytes, at: 3),
                payload: .move(
                    fingerCount: bytes[2],
                    dx: Self.readFloatLE(bytes, at: 7),
                    dy: Self.readFloatLE(bytes, at: 11)
                )
            )

        case .click:
            guard let button = Button(rawValue: bytes[2]),
                  let phase = Phase(rawValue: bytes[3]) else { return nil }
            return Packet(
                type: .click,
                timestampMs: Self.readUInt32LE(bytes, at: 4),
                payload: .click(button: button, phase: phase)
            )

        case .scroll:
            return Packet(
                type: .scroll,
                timestampMs: Self.readUInt32LE(bytes, at: 3),
                payload: .scroll(
                    fingerCount: bytes[2],
                    dx: Self.readFloatLE(bytes, at: 7),
                    dy: Self.readFloatLE(bytes, at: 11)
                )
            )

        case .gesture:
            return Packet(
                type: .gesture,
                timestampMs: Self.readUInt32LE(bytes, at: 5),
                payload: .gesture(actionCode: bytes[2], origin: bytes[3], direction: bytes[4])
            )
        }
    }

    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }

    private static func readFloatLE(_ bytes: [UInt8], at offset: Int) -> Float {
        Float(bitPattern: readUInt32LE(bytes, at: offset))
    }
}
