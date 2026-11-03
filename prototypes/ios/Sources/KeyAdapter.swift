import CryptoKit
import Foundation
import LocalAuthentication
import Security

// LAContext supports invalidation while the associated OS operation is pending.
// This immutable box only shares the context with the worker performing that operation.
final class AuthenticationContext: @unchecked Sendable {
    let value = LAContext()
    init(interactionAllowed: Bool = true) {
        value.touchIDAuthenticationAllowableReuseDuration = 0
        value.localizedFallbackTitle = ""
        value.localizedCancelTitle = "取消"
        value.localizedReason = "Vault の検証用鍵操作を認証します"
        value.interactionNotAllowed = !interactionAllowed
    }
    deinit { value.invalidate() }
}

struct KeyAdapter: Sendable {
    let backend: Backend
    let namespace: String

    private func account(_ profile: String, _ purpose: Int) -> String {
        "\(namespace).\(backend.rawValue).\(profile).\(purpose)"
    }

    private func query(_ profile: String, _ purpose: Int) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "dev.vault.ios.prototype",
         kSecAttrAccount as String: account(profile, purpose),
         kSecAttrSynchronizable as String: false]
    }

    func create(profile: String, purpose: Int) throws -> Data {
        let publicKey: Data
        var representation: Data
        switch backend {
        case .softwareSimulator:
            #if targetEnvironment(simulator) || os(macOS)
            let key = P256.KeyAgreement.PrivateKey()
            publicKey = key.publicKey.x963Representation
            representation = key.rawRepresentation
            #else
            throw VaultFailure("UNSUPPORTED")
            #endif
        case .secureEnclave:
            guard SecureEnclave.isAvailable else { throw VaultFailure("UNSUPPORTED") }
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], &error) else {
                throw VaultFailure("ACCESS_CONTROL_FAILED")
            }
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control)
            publicKey = key.publicKey.x963Representation
            representation = key.dataRepresentation
        }
        defer { representation.resetBytes(in: 0..<representation.count) }
        var attributes = query(profile, purpose)
        attributes[kSecValueData as String] = representation
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw keychainError(status) }
        return publicKey
    }

    func delete(profile: String, purpose: Int) throws {
        let status = SecItemDelete(query(profile, purpose) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw keychainError(status) }
    }

    private func load(profile: String, purpose: Int) throws -> Data {
        var attributes = query(profile, purpose)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw status == errSecItemNotFound ? VaultFailure("KEY_INVALIDATED") : keychainError(status)
        }
        return data
    }

    private func keychainError(_ status: OSStatus) -> VaultFailure {
        switch status {
        case errSecDuplicateItem: return VaultFailure("KEY_EXISTS")
        case errSecMissingEntitlement: return VaultFailure("KEYCHAIN_ENTITLEMENT_MISSING")
        case errSecInteractionNotAllowed: return VaultFailure("KEYCHAIN_LOCKED")
        default: return VaultFailure("KEY_STORAGE_OSSTATUS_\(status)")
        }
    }

    private func binding(profile: String, purpose: Int) -> Data {
        Data("vault-ios/wrap/v1|\(backend.rawValue)|\(profile)|\(purpose)|1".utf8)
    }

    func wrap(_ dek: Data, publicKey: Data, profile: String, purpose: Int) throws -> KeyWrap {
        guard dek.count == 32, (1...2).contains(purpose) else { throw VaultFailure("INVALID_INPUT") }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
        var salt = Data(repeating: 0, count: 32)
        let result = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard result == errSecSuccess else { throw VaultFailure("RANDOM_FAILED") }
        let info = binding(profile: profile, purpose: purpose)
        let kek = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let sealed = try AES.GCM.seal(dek, using: kek, nonce: AES.GCM.Nonce(), authenticating: info)
        guard let combined = sealed.combined else { throw VaultFailure("INTERNAL_ERROR") }
        return KeyWrap(backend: backend, ephemeralPublicKey: ephemeral.publicKey.x963Representation,
                       salt: salt, sealed: combined)
    }

    // In Secure Enclave mode the protected key agreement itself invokes the OS
    // authentication constraint. A successful evaluatePolicy boolean is not used.
    func unwrap(_ wrap: KeyWrap, profile: String, purpose: Int,
                context: AuthenticationContext) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            try unwrapSync(wrap, profile: profile, purpose: purpose, context: context)
        }.value
    }

    func unwrapSync(_ wrap: KeyWrap, profile: String, purpose: Int,
                    context: AuthenticationContext) throws -> Data {
        guard wrap.backend == backend, wrap.salt.count == 32, wrap.sealed.count == 60,
              wrap.ephemeralPublicKey.count == 65, (1...2).contains(purpose) else {
            throw VaultFailure("INVALID_INPUT")
        }
        var representation = try load(profile: profile, purpose: purpose)
        defer { representation.resetBytes(in: 0..<representation.count) }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: wrap.ephemeralPublicKey)
        let shared: SharedSecret
        switch backend {
        case .softwareSimulator:
            #if targetEnvironment(simulator) || os(macOS)
            shared = try P256.KeyAgreement.PrivateKey(rawRepresentation: representation).sharedSecretFromKeyAgreement(with: peer)
            #else
            throw VaultFailure("UNSUPPORTED")
            #endif
        case .secureEnclave:
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation,
                authenticationContext: context.value)
            shared = try key.sharedSecretFromKeyAgreement(with: peer)
        }
        let info = binding(profile: profile, purpose: purpose)
        let kek = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: wrap.salt, sharedInfo: info, outputByteCount: 32)
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: wrap.sealed), using: kek, authenticating: info)
        } catch { throw VaultFailure("INTEGRITY_FAILED") }
    }
}
