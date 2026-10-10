import Foundation
import CryptoKit

/// A device the Mac trusts after pairing.
public struct TrustedDevice: Codable, Equatable {
    public let deviceId: Data
    public let name: String
    public let publicKey: Data
    public let addedAt: Date

    public init(deviceId: Data, name: String, publicKey: Data, addedAt: Date = Date()) {
        self.deviceId = deviceId
        self.name = name
        self.publicKey = publicKey
        self.addedAt = addedAt
    }
}

/// JSON file store for paired devices (Application Support/AirPad).
public final class TrustedDeviceStore {
    private let fileURL: URL
    private let queue = DispatchQueue(label: "airpad.trusteddevices")

    public init(directory: URL? = nil) {
        let dir = directory ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AirPad", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("trusted_devices.json")
    }

    public func loadAll() -> [TrustedDevice] {
        queue.sync {
            guard let data = try? Data(contentsOf: fileURL),
                  let devices = try? JSONDecoder().decode([TrustedDevice].self, from: data) else { return [] }
            return devices
        }
    }

    public func find(deviceId: Data) -> TrustedDevice? {
        loadAll().first { $0.deviceId == deviceId }
    }

    public func add(_ device: TrustedDevice) {
        queue.sync {
            var devices = (try? JSONDecoder().decode([TrustedDevice].self, from: (try? Data(contentsOf: fileURL)) ?? Data())) ?? []
            devices.removeAll { $0.deviceId == device.deviceId }
            devices.append(device)
            if let data = try? JSONEncoder().encode(devices) {
                try? data.write(to: fileURL, options: .atomic)
            }
        }
    }

    public func remove(deviceId: Data) {
        queue.sync {
            guard let data = try? Data(contentsOf: fileURL),
                  var devices = try? JSONDecoder().decode([TrustedDevice].self, from: data) else { return }
            devices.removeAll { $0.deviceId == deviceId }
            if let out = try? JSONEncoder().encode(devices) {
                try? out.write(to: fileURL, options: .atomic)
            }
        }
    }
}

/// The Mac's long-term identity: P-256 keypair in the Keychain plus a random
/// 16-byte macId persisted in UserDefaults.
public final class MacIdentity {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let macId: Data
    public let macName: String

    private static let keychainService = "com.diego.airpad.identity"
    private static let macIdDefaultsKey = "airpad.macId"

    public init(macName: String = Host.current().localizedName ?? "Mac",
                defaults: UserDefaults = .standard) {
        self.macName = macName
        Self.migrate()

        if let raw = Self.loadKeychainBytes(), let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) {
            privateKey = key
        } else {
            let key = P256.KeyAgreement.PrivateKey()
            Self.saveKeychainBytes(key.rawRepresentation)
            privateKey = key
        }

        if let id = defaults.data(forKey: Self.macIdDefaultsKey), id.count == PairingProtocol.deviceIdLength {
            macId = id
        } else {
            let id = AirPadCrypto.randomBytes(PairingProtocol.deviceIdLength)
            defaults.set(id, forKey: Self.macIdDefaultsKey)
            macId = id
        }
    }

    public var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }

    public var publicKeyData: Data { privateKey.publicKey.x963Representation }

    /// One-time migration from the previous experimental storage location.
    private static func migrate() {
        guard !UserDefaults.standard.bool(forKey: "airpad.identity.migrated") else { return }
        UserDefaults.standard.set(true, forKey: "airpad.identity.migrated")
    }

    private static func loadKeychainBytes() -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: "p256-raw",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        _ = query.removeValue(forKey: kSecReturnData as String) == nil
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    private static func saveKeychainBytes(_ data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: "p256-raw"
        ]
        SecItemDelete(query as CFDictionary)
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
