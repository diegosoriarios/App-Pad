import Foundation
import os
import CoreBluetooth
import Combine
import AirPadCore

final class BLECentralManager: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    static let serviceUUID = CBUUID(string: "9A3B0001-1234-4567-89AB-CDEF01234567")
    static let touchCharacteristicUUID = CBUUID(string: "9A3B0002-1234-4567-89AB-CDEF01234567")

    enum PairingPhase: Equatable {
        case idle              // not connected
        case connecting
        case negotiating       // handshake in progress
        case ready             // encrypted traffic flowing
        case pairingNeeded     // phone unknown -> show QR / PIN
        case failed(String)
    }

    @Published var connectionStatus: String = "Initializing Bluetooth..."
    @Published var isConnected: Bool = false
    @Published var lastLatencyMs: Double = 0.0
    @Published var packetCount: Int = 0
    @Published var lastEventDescription: String = "—"
    @Published var pairingPhase: PairingPhase = .idle
    @Published var trustedDevices: [TrustedDevice] = []
    @Published var pairingOffer: PairingProtocol.PairingOffer?

    private var centralManager: CBCentralManager!
    private var targetPeripheral: CBPeripheral?
    private let log = Logger(subsystem: "com.diego.AppPad-Mac", category: "BLE")
    private var touchCharacteristic: CBCharacteristic?
    private var handshakeStarted = false

    private let cursorInjector: CursorInjector
    private let identity: MacIdentity
    private let deviceStore: TrustedDeviceStore

    // Secure session state
    private var session: MacPairingSession?
    private var defragmenter = PairingProtocol.Defragmenter()
    private var inboundCipher: PairingProtocol.TrafficCipher?

    // Latency calculation tracking (PROTOCOL.md: clock alignment on first packet)
    private var initialAndroidTimestamp: UInt32?
    private var initialMacTime: TimeInterval?

    init(cursorInjector: CursorInjector, identity: MacIdentity, deviceStore: TrustedDeviceStore) {
        self.cursorInjector = cursorInjector
        self.identity = identity
        self.deviceStore = deviceStore
        super.init()
        trustedDevices = deviceStore.loadAll()
        refreshPairingOffer()
        self.centralManager = CBCentralManager(delegate: self, queue: .main)
    }

    // MARK: - Pairing offer (QR / PIN shown in the menu)

    func refreshPairingOffer() {
        let offer = PairingProtocol.PairingOffer(
            macId: identity.macId,
            macName: identity.macName,
            identityPub: identity.publicKeyData,
            qrOtp: PairingProtocol.randomOTP(),
            pin: PairingProtocol.randomPIN()
        )
        pairingOffer = offer
    }

    func regeneratePairingOffer() {
        refreshPairingOffer()
        // Adopt the new OTP immediately if no session is active yet.
        if targetPeripheral == nil {
            startSession(mode: .pairing(otpCandidates: pairingOffer!.otpCandidates))
        }
    }

    func removeDevice(_ device: TrustedDevice) {
        deviceStore.remove(deviceId: device.deviceId)
        trustedDevices = deviceStore.loadAll()
    }

    // MARK: - Session management

    private func startSession(mode: MacPairingSession.Mode) {
        session = MacPairingSession(mode: mode, identity: identity) { [weak self] deviceId in
            self?.deviceStore.find(deviceId: deviceId)
        }
        inboundCipher = nil
        for (type, payload) in session?.start() ?? [] {
            writeControlMessage(type: type, payload: payload)
        }
    }

    private func beginHandshake() {
        defragmenter.reset()
        initialAndroidTimestamp = nil
        initialMacTime = nil
        pairingPhase = .negotiating
        connectionStatus = "Negotiating secure session..."
        startSession(mode: .reconnect)
    }

    private func handleSessionResult(_ result: MacPairingSession.HandleResult) {
        for event in result.events {
            log.info("[BLE] session event: \(String(describing: event), privacy: .public)")
        }
        for (type, payload) in result.frames {
            writeControlMessage(type: type, payload: payload)
        }
        for event in result.events {
            switch event {
            case .devicePaired(let device):
                deviceStore.add(device)
                trustedDevices = deviceStore.loadAll()
            case .ready(let keys):
                inboundCipher = .sender(for: keys, fromAndroid: true)
                pairingPhase = .ready
                connectionStatus = "AirPad Ready (encrypted)"
            case .failed(let reason):
                pairingPhase = .failed(reason)
                connectionStatus = "Pairing failed: \(reason)"
            case .unknownDevice:
                pairingPhase = .pairingNeeded
                connectionStatus = "Unknown phone — pair via QR or PIN"
            }
        }
    }

    private func writeControlMessage(type: UInt8, payload: Data) {
        guard let peripheral = targetPeripheral, let characteristic = touchCharacteristic else {
            log.info("[BLE] TX dropped type=0x\(String(type, radix: 16), privacy: .public)")
            return
        }
        let frames = PairingProtocol.chunkMessage(type: type, payload: payload)
        log.info("[BLE] TX type=0x\(String(type, radix: 16), privacy: .public) payload=\(payload.count, privacy: .public)B chunks=\(frames.count, privacy: .public)")
        for frame in frames {
            peripheral.writeValue(frame, for: characteristic, type: .withResponse)
        }
    }

    // MARK: - Scanning

    func startScanning() {
        guard centralManager.state == .poweredOn else {
            connectionStatus = "Bluetooth is Off"
            return
        }
        connectionStatus = "Scanning for AirPad..."
        // Scan unfiltered: Android phones often overflow the legacy 31-byte
        // advertisement (device name + 128-bit UUID), dropping the service
        // UUID from the main packet — a filtered scan can then never match.
        // The client-side check in didDiscover identifies the phone instead.
        centralManager.scanForPeripherals(withServices: nil, options: [
            CBCentralManagerScanOptionAllowDuplicatesKey: false
        ])
    }

    /// Matches an AirPad phone: advertised service UUID contains ours, or the
    /// manufacturer data carries our marker (vendor ID 0xFFFF + "AP").
    private func isAirPadPeripheral(advertisementData: [String: Any]) -> Bool {
        if let services = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID],
           services.contains(BLECentralManager.serviceUUID) {
            return true
        }
        if let manufacturerData = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
           manufacturerData.count >= 4,
           manufacturerData[manufacturerData.startIndex] == 0xFF,
           manufacturerData[manufacturerData.startIndex + 1] == 0xFF,
           manufacturerData[manufacturerData.startIndex + 2] == 0x41, // 'A'
           manufacturerData[manufacturerData.startIndex + 3] == 0x50  // 'P'
        {
            return true
        }
        return false
    }

    func stopScanning() {
        centralManager.stopScan()
    }

    // MARK: - CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            connectionStatus = "Bluetooth Powered On. Scanning..."
            startScanning()
        case .poweredOff:
            connectionStatus = "Bluetooth is Turned Off"
            isConnected = false
            pairingPhase = .idle
        case .unauthorized:
            connectionStatus = "Bluetooth Permission Denied"
            isConnected = false
        case .unsupported:
            connectionStatus = "BLE Unsupported on this Mac"
            isConnected = false
        default:
            connectionStatus = "Bluetooth State: \(central.state.rawValue)"
            isConnected = false
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        guard isAirPadPeripheral(advertisementData: advertisementData) else { return }
        connectionStatus = "Discovered AirPad (\(peripheral.name ?? "Device")). Connecting..."
        pairingPhase = .connecting
        centralManager.stopScan()
        targetPeripheral = peripheral
        targetPeripheral?.delegate = self
        centralManager.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connectionStatus = "Connected. Discovering Services..."
        isConnected = true
        handshakeStarted = false
        peripheral.discoverServices([BLECentralManager.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        isConnected = false
        connectionStatus = "Disconnected. Rescanning..."
        cursorInjector.resetState()
        targetPeripheral = nil
        touchCharacteristic = nil
        session = nil
        inboundCipher = nil
        defragmenter.reset()
        pairingPhase = .idle
        initialAndroidTimestamp = nil
        initialMacTime = nil
        handshakeStarted = false
        startScanning()
    }

    // MARK: - CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error = error {
            connectionStatus = "Service discovery failed: \(error.localizedDescription)"
            return
        }

        guard let services = peripheral.services else { return }
        for service in services where service.uuid == BLECentralManager.serviceUUID {
            connectionStatus = "Discovered AirPad Service. Discovering Characteristics..."
            peripheral.discoverCharacteristics([BLECentralManager.touchCharacteristicUUID], for: service)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error = error {
            connectionStatus = "Characteristic discovery failed: \(error.localizedDescription)"
            return
        }

        guard let characteristics = service.characteristics else { return }
        for characteristic in characteristics where characteristic.uuid == BLECentralManager.touchCharacteristicUUID {
            touchCharacteristic = characteristic
            // Do NOT start the handshake here: the phone drops its reply
            // notifications unless the CCCD write has already completed.
            // beginHandshake() runs in didUpdateNotificationStateFor.
            peripheral.setNotifyValue(true, for: characteristic)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            log.info("[BLE] subscribe error: \(error.localizedDescription, privacy: .public)")
            connectionStatus = "Subscribe failed: \(error.localizedDescription)"
            return
        }
        log.info("[BLE] notifying=\(characteristic.isNotifying, privacy: .public) started=\(self.handshakeStarted, privacy: .public)")
        guard characteristic.uuid == BLECentralManager.touchCharacteristicUUID, characteristic.isNotifying, !handshakeStarted else { return }
        handshakeStarted = true
        beginHandshake()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            log.info("[BLE] value error: \(error.localizedDescription, privacy: .public)")
            return
        }

        guard let data = characteristic.value, !data.isEmpty else { return }
        log.info("[BLE] RX \(data.count, privacy: .public)B: \(data.map { String(format: "%02x", $0) }.joined(), privacy: .public)")

        if inboundCipher != nil {
            handleTrafficFrame(data)
        } else {
            handleControlFrame(data)
        }
    }

    // MARK: - Secure session data path

    private func handleControlFrame(_ frame: Data) {
        guard let (type, payload) = defragmenter.feed(frame) else { return }
        log.info("[BLE] assembled type=0x\(String(type, radix: 16), privacy: .public) payload=\(payload.count, privacy: .public)B")

        // Phone initiates pairing (scanned QR / entered PIN) while we were
        // in reconnect mode: rebuild the session in pairing mode and re-feed.
        if type == PairingProtocol.msgPairingRequest, session?.isReady != true {
            if pairingOffer == nil { refreshPairingOffer() }
            session = MacPairingSession(mode: .pairing(otpCandidates: pairingOffer!.otpCandidates), identity: identity) { [weak self] deviceId in
                self?.deviceStore.find(deviceId: deviceId)
            }
            pairingPhase = .negotiating
        }

        guard let session = session else { return }
        handleSessionResult(session.handle(type: type, payload: payload))
    }

    private func handleTrafficFrame(_ frame: Data) {
        guard let v1Packet = inboundCipher?.decrypt(frame: frame) else { return }
        routeV1Packet(v1Packet)
    }

    private func routeV1Packet(_ packet: Data) {
        guard packet.count == PairingProtocol.TrafficCipher.v1PacketLength else { return }
        let bytes = [UInt8](packet)

        // Timestamp offset differs per packet type (PROTOCOL.md §8).
        let timestampOffset: Int
        switch bytes[1] {
        case 0x02: timestampOffset = 4  // click
        case 0x04: timestampOffset = 5  // gesture
        default: timestampOffset = 3    // move / scroll
        }
        let timestampMs = UInt32(bytes[timestampOffset])
            | UInt32(bytes[timestampOffset + 1]) << 8
            | UInt32(bytes[timestampOffset + 2]) << 16
            | UInt32(bytes[timestampOffset + 3]) << 24
        recordLatency(timestampMs)

        switch bytes[1] {
        case 0x01: // move
            let dx = Float(bitPattern: UInt32(bytes[7]) | UInt32(bytes[8]) << 8 | UInt32(bytes[9]) << 16 | UInt32(bytes[10]) << 24)
            let dy = Float(bitPattern: UInt32(bytes[11]) | UInt32(bytes[12]) << 8 | UInt32(bytes[13]) << 16 | UInt32(bytes[14]) << 24)
            cursorInjector.moveCursor(dx: dx, dy: dy)
            lastEventDescription = "Move (\(bytes[2]) finger\(bytes[2] == 1 ? "" : "s")) · \(String(format: "%.1f", dx)), \(String(format: "%.1f", dy))"

        case 0x02: // click
            guard let button = AirPadPacket.Button(rawValue: bytes[2]),
                  let phase = AirPadPacket.Phase(rawValue: bytes[3]) else { return }
            cursorInjector.click(button: button, phase: phase)
            lastEventDescription = "Click \(button == .left ? "Left" : "Right") \(phase == .press ? "press" : "release")"

        case 0x03: // scroll
            let dx = Float(bitPattern: UInt32(bytes[7]) | UInt32(bytes[8]) << 8 | UInt32(bytes[9]) << 16 | UInt32(bytes[10]) << 24)
            let dy = Float(bitPattern: UInt32(bytes[11]) | UInt32(bytes[12]) << 8 | UInt32(bytes[13]) << 16 | UInt32(bytes[14]) << 24)
            cursorInjector.scroll(dx: dx, dy: dy)
            lastEventDescription = "Scroll · \(String(format: "%.1f", dx)), \(String(format: "%.1f", dy))"

        case 0x04: // gesture event
            let actionRaw = bytes[2]
            guard let action = GestureAction(rawValue: actionRaw), action != .disabled else {
                lastEventDescription = "Gesture (unknown action 0x\(String(actionRaw, radix: 16)))"
                return
            }
            cursorInjector.gestureAction(rawCode: actionRaw)
            let mapped = GestureActionMapping.shortcut(for: action) != nil
            lastEventDescription = "Gesture → \(action.displayName)\(mapped ? "" : " (unmapped)")"

        default:
            break
        }
    }

    // MARK: - Latency

    private func recordLatency(_ timestampMs: UInt32) {
        let nowMacTime = ProcessInfo.processInfo.systemUptime

        if initialAndroidTimestamp == nil || initialMacTime == nil {
            initialAndroidTimestamp = timestampMs
            initialMacTime = nowMacTime
            packetCount += 1
            return
        }

        let androidElapsedMs = Double(timestampMs &- initialAndroidTimestamp!)
        let macElapsedMs = (nowMacTime - initialMacTime!) * 1000.0
        let estimatedLatency = max(0.0, macElapsedMs - androidElapsedMs)

        lastLatencyMs = estimatedLatency
        packetCount += 1
    }
}
