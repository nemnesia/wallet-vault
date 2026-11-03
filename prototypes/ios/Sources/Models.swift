import Foundation

struct VaultFailure: Error, Equatable {
    let code: String
    init(_ code: String) { self.code = code }
}

enum Backend: String, Codable, CaseIterable, Sendable {
    case softwareSimulator = "SOFTWARE_SIMULATOR"
    case secureEnclave = "SECURE_ENCLAVE"
}

struct Records: Codable, Sendable {
    let id: String
    let label: String
    var profileRecord: String
    var signingRecord: String
}

struct KeyWrap: Codable, Sendable {
    let backend: Backend
    let ephemeralPublicKey: Data
    let salt: Data
    var sealed: Data
}

struct Snapshot: Codable, Sendable {
    let version: Int
    let backend: Backend
    let records: Records
    let profileWrap: KeyWrap
    let signingWrap: KeyWrap

    func validate() throws {
        guard version == 1, records.id.count == 32,
              records.id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !records.label.isEmpty, records.label.utf8.count <= 64,
              profileWrap.backend == backend, signingWrap.backend == backend else {
            throw VaultFailure("INVALID_INPUT")
        }
        _ = try RustBridge.command("validate", value: records)
        for wrap in [profileWrap, signingWrap] {
            guard wrap.salt.count == 32, wrap.ephemeralPublicKey.count == 65,
                  wrap.sealed.count == 60 else { throw VaultFailure("INVALID_INPUT") }
        }
    }
}

enum RustBridge {
    static func command<T: Encodable>(_ action: String, value: T, secret: Data = Data()) throws -> [String: Any] {
        try command(action, json: JSONEncoder().encode(value), secret: secret)
    }

    @discardableResult
    static func command(_ action: String, arguments: [String: Any] = [:], secret: Data = Data()) throws -> [String: Any] {
        try command(action, json: JSONSerialization.data(withJSONObject: arguments), secret: secret)
    }

    private static func command(_ action: String, json: Data, secret: Data) throws -> [String: Any] {
        let actionBytes = Array(action.utf8)
        var output = [UInt8](repeating: 0, count: 32768)
        let length = actionBytes.withUnsafeBufferPointer { a in
            json.withUnsafeBytes { j in
                secret.withUnsafeBytes { s in
                    vault_ios_command(a.baseAddress, a.count, j.bindMemory(to: UInt8.self).baseAddress,
                        j.count, s.bindMemory(to: UInt8.self).baseAddress, s.count, &output, output.count)
                }
            }
        }
        guard length > 0, length <= output.count,
              let response = try JSONSerialization.jsonObject(with: Data(output.prefix(length))) as? [String: Any] else {
            throw VaultFailure("INTERNAL_ERROR")
        }
        if let error = response["error"] as? String { throw VaultFailure(error) }
        guard let result = response["ok"] as? [String: Any] else { throw VaultFailure("INTERNAL_ERROR") }
        return result
    }

    static func registrationKey(_ purpose: Int32) throws -> Data {
        var key = Data(repeating: 0, count: 32)
        let result = key.withUnsafeMutableBytes { bytes in
            vault_ios_registration_key(purpose, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        guard result == 0 else { throw VaultFailure("INVALID_STATE") }
        return key
    }

    static func registration() throws -> Records {
        let value = try command("registration")
        return try JSONDecoder().decode(Records.self, from: JSONSerialization.data(withJSONObject: value))
    }
}
