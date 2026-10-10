import SwiftUI
import AirPadCore

struct ContentView: View {
    @ObservedObject var bleManager: BLECentralManager
    @ObservedObject var cursorInjector: CursorInjector

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            statusSection

            if bleManager.isConnected {
                statsSection
                Divider()
            }

            accessibilitySection
            Divider()
            pairingSection
            Divider()
            HStack {
                Spacer()
                Button("Quit AirPad") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.plain)
                .font(.caption)
                .foregroundColor(.secondary)
            }
        }
        .padding(16)
        .frame(width: 320)
    }

    // MARK: - Sections

    private var header: some View {
        HStack {
            Image(systemName: "hand.tap.fill")
                .font(.title2)
                .foregroundColor(.accentColor)
            Text("AirPad Receiver")
                .font(.headline)
            Spacer()
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
        }
    }

    private var statusColor: Color {
        if bleManager.pairingPhase == .ready { return .green }
        if bleManager.isConnected { return .orange }
        return .gray
    }

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Status")
                .font(.caption)
                .foregroundColor(.secondary)
            Text(bleManager.connectionStatus)
                .font(.subheadline)
                .fontWeight(.medium)
        }
    }

    private var statsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Est. Delay")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(String(format: "%.1f ms", bleManager.lastLatencyMs))
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                        .foregroundColor(bleManager.lastLatencyMs < 20.0 ? .green : .yellow)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text("Packets Recv")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("\(bleManager.packetCount)")
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                }
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)

            VStack(alignment: .leading, spacing: 2) {
                Text("Last Event")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(bleManager.lastEventDescription)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
    }

    private var accessibilitySection: some View {
        Group {
            if !cursorInjector.isAccessibilityGranted {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text("Accessibility Permission Required")
                            .font(.caption)
                            .fontWeight(.bold)
                            .foregroundColor(.red)
                    }
                    Text("AirPad needs Accessibility access to move the Mac cursor.")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Button(action: {
                        cursorInjector.requestAccessibilityPermissions()
                    }) {
                        Text("Grant Permission in Settings")
                            .font(.caption)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(10)
                .background(Color.red.opacity(0.1))
                .cornerRadius(8)
            } else {
                HStack {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    Text("Accessibility Permission Granted")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private var pairingSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Pairing")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                if bleManager.pairingPhase == .pairingNeeded || bleManager.pairingPhase == .negotiating {
                    Text(bleManager.pairingPhase == .pairingNeeded ? "New phone" : "Negotiating…")
                        .font(.caption2)
                        .fontWeight(.bold)
                        .foregroundColor(.orange)
                }
            }

            if case .failed(let reason) = bleManager.pairingPhase {
                Text(reason)
                    .font(.caption2)
                    .foregroundColor(.red)
            }

            if let offer = bleManager.pairingOffer, let qrText = qrPayload(for: offer),
               let image = QRCodeImage.make(from: qrText) {
                VStack(spacing: 8) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        // The QR payload is ~200 bytes (~29x29 modules); at a
                        // smaller size phone cameras struggle with screen
                        // moiré and often fail to decode.
                        .frame(width: 240, height: 240)
                        .background(Color.white)
                        .cornerRadius(6)

                    Text("Scan with AirPad on your phone")
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    Divider()

                    Text("No camera? Enter this PIN in the app:")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(offer.pin)
                        .font(.system(.title3, design: .monospaced))
                        .fontWeight(.bold)
                        .textSelection(.enabled)
                        .tracking(4)
                }
                .frame(maxWidth: .infinity)
                .padding(8)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(8)

                Button("New Code") {
                    bleManager.regeneratePairingOffer()
                }
                .font(.caption)
                .frame(maxWidth: .infinity)
            }

            let devices = bleManager.trustedDevices
            if !devices.isEmpty {
                Text("Paired devices")
                    .font(.caption)
                    .foregroundColor(.secondary)
                ForEach(devices, id: \.deviceId) { device in
                    HStack {
                        Image(systemName: "iphone")
                            .foregroundColor(.secondary)
                        Text(device.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Button {
                            bleManager.removeDevice(device)
                        } label: {
                            Image(systemName: "trash")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.plain)
                        .help("Remove device")
                    }
                }
            }
        }
    }

    // MARK: - Helpers

    private func qrPayload(for offer: PairingProtocol.PairingOffer) -> String? {
        let text = PairingProtocol.encodeOfferQR(offer)
        return text.isEmpty ? nil : text
    }
}
