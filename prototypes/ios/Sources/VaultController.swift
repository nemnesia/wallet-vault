import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
protocol BiometricAuthenticating {
    func authenticate(_ context: AuthenticationContext) async throws
}

@MainActor
struct SystemBiometrics: BiometricAuthenticating {
    func authenticate(_ context: AuthenticationContext) async throws {
        guard try await context.value.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Vault の Simulator 用ソフトウェア鍵を使います") else {
            throw VaultFailure("AUTH_FAILED")
        }
    }
}

@MainActor
final class VaultController: ObservableObject {
    @Published private(set) var backend: Backend
    @Published private(set) var snapshots: [Snapshot] = []
    @Published private(set) var selectedID: String?
    @Published private(set) var state = "locked"
    @Published private(set) var result = "READY"
    @Published private(set) var busy = false
    @Published private(set) var events: [String] = []
    @Published private(set) var biometry = "未確認"
    @Published private(set) var requestID: String?
    private var gate = OperationGate()
    private var context: AuthenticationContext?
    private var timeout: Task<Void, Never>?
    private var deadline: UInt64 = 0
    private let root: URL
    private let namespace: String
    private let authenticator: any BiometricAuthenticating
    private let clock: () -> UInt64

    init(backend: Backend, root: URL, namespace: String = "interactive-v1",
         authenticator: any BiometricAuthenticating = SystemBiometrics(),
         clock: @escaping () -> UInt64 = { UInt64(ProcessInfo.processInfo.systemUptime * 1000) }) {
        self.backend = backend
        self.root = root
        self.namespace = namespace
        self.authenticator = authenticator
        self.clock = clock
        _ = try? RustBridge.command("lock")
        reload()
        refreshBiometry()
    }

    var selected: Snapshot? { snapshots.first { $0.records.id == selectedID } }
    var adapter: KeyAdapter { KeyAdapter(backend: backend, namespace: namespace) }
    var store: SnapshotStore { get throws { try SnapshotStore(root: root, backend: backend) } }

    func refreshBiometry() {
        let probe = LAContext()
        defer { probe.invalidate() }
        var error: NSError?
        let available = probe.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        let kind = probe.biometryType == .faceID ? "Face ID" : (probe.biometryType == .touchID ? "Touch ID" : "生体認証なし")
        biometry = "\(kind) / \(available ? "利用可能" : Self.classify(error))"
    }

    func reload() {
        do {
            snapshots = try store.load()
            if !snapshots.contains(where: { $0.records.id == selectedID }) { selectedID = snapshots.first?.records.id }
        } catch { record("STORAGE_CORRUPT") }
    }

    func select(_ id: String) {
        guard !busy, snapshots.contains(where: { $0.records.id == id }) else { return }
        lock()
        selectedID = id
    }

    func switchBackend(_ next: Backend) {
        guard !busy else { return }
        #if !targetEnvironment(simulator)
        guard next == .secureEnclave else { record("UNSUPPORTED"); return }
        #endif
        lock()
        backend = next
        selectedID = nil
        reload()
    }

    func lock(background: Bool = false) {
        gate.cancel()
        context?.value.invalidate()
        context = nil
        timeout?.cancel()
        timeout = nil
        busy = false
        requestID = nil
        _ = try? RustBridge.command("lock")
        syncState()
        record(background ? "LOCKED_BACKGROUND" : "LOCKED")
    }

    func cancel(code: String = "CANCELLED") {
        gate.cancel()
        context?.value.invalidate()
        context = nil
        timeout?.cancel()
        timeout = nil
        busy = false
        requestID = nil
        _ = try? RustBridge.command("cancel")
        syncState()
        record(code)
    }

    private func ensure(_ id: UUID) throws {
        guard gate.pending == id else { throw VaultFailure("CANCELLED") }
        guard clock() < deadline else { throw VaultFailure("EXPIRED") }
    }

    private func syncState() {
        state = (try? RustBridge.command("status")["state"] as? String) ?? "locked"
    }

    private func record(_ code: String) {
        result = code
        events = Array((events + [code]).suffix(80))
    }

    private func perform(success: String, body: (UUID) async throws -> Void) async throws {
        guard let id = gate.begin() else { throw VaultFailure("BUSY") }
        busy = true
        deadline = clock() + 60000
        record("AUTHENTICATING")
        timeout = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(60)) } catch { return }
            guard let self, self.gate.pending == id else { return }
            self.cancel(code: "EXPIRED")
        }
        do {
            try await body(id)
            try ensure(id)
            _ = gate.complete(id)
            context?.value.invalidate()
            context = nil
            timeout?.cancel()
            timeout = nil
            busy = false
            syncState()
            record(success)
        } catch {
            // A late callback must never cancel a replacement operation or alter its state.
            guard gate.complete(id) else { throw VaultFailure("CANCELLED") }
            context?.value.invalidate()
            context = nil
            timeout?.cancel()
            timeout = nil
            busy = false
            requestID = nil
            _ = try? RustBridge.command("cancel")
            syncState()
            let code = Self.classify(error)
            record(code)
            throw VaultFailure(code)
        }
    }

    private func unwrap(_ wrap: KeyWrap, profile: String, purpose: Int, operation: UUID) async throws -> Data {
        try ensure(operation)
        context?.value.invalidate()
        let next = AuthenticationContext()
        context = next
        if backend == .softwareSimulator {
            try await authenticator.authenticate(next)
            try ensure(operation)
        } else {
            var error: NSError?
            guard next.value.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                throw VaultFailure(Self.classify(error))
            }
        }
        var dek = try await adapter.unwrap(wrap, profile: profile, purpose: purpose, context: next)
        do { try ensure(operation) } catch {
            dek.resetBytes(in: 0..<dek.count)
            throw error
        }
        return dek
    }

    func register(label: String, abort: Bool = false) async throws {
        guard state == "locked" else { throw VaultFailure("INVALID_STATE") }
        try await perform(success: "SAVED_LOCKED") { operation in
            _ = try RustBridge.command("start", arguments: ["label": label])
            let records = try RustBridge.registration()
            let currentAdapter = adapter
            var created: [Int] = []
            var committed = false
            defer {
                if !committed {
                    for purpose in created { try? currentAdapter.delete(profile: records.id, purpose: purpose) }
                }
            }
            let profilePublic = try currentAdapter.create(profile: records.id, purpose: 1)
            created.append(1)
            let signingPublic = try currentAdapter.create(profile: records.id, purpose: 2)
            created.append(2)
            let (p, s): (KeyWrap, KeyWrap) = try {
                var profileDEK = try RustBridge.registrationKey(1)
                var signingDEK = try RustBridge.registrationKey(2)
                defer {
                    profileDEK.resetBytes(in: 0..<profileDEK.count)
                    signingDEK.resetBytes(in: 0..<signingDEK.count)
                }
                return (try currentAdapter.wrap(profileDEK, publicKey: profilePublic, profile: records.id, purpose: 1),
                        try currentAdapter.wrap(signingDEK, publicKey: signingPublic, profile: records.id, purpose: 2))
            }()
            // Verify both protected private key operations before committing a Profile.
            for (purpose, wrap) in [(1, p), (2, s)] {
                var verified = try await unwrap(wrap, profile: records.id, purpose: purpose, operation: operation)
                var expected = try RustBridge.registrationKey(Int32(purpose))
                defer {
                    verified.resetBytes(in: 0..<verified.count)
                    expected.resetBytes(in: 0..<expected.count)
                }
                guard verified == expected else { throw VaultFailure("INTEGRITY_FAILED") }
            }
            try ensure(operation)
            let snapshot = Snapshot(version: 1, backend: backend, records: records, profileWrap: p, signingWrap: s)
            try store.save(snapshot, abort: abort)
            committed = true
            _ = try RustBridge.command("lock")
            snapshots = try store.load()
            selectedID = records.id
        }
    }

    func open(tamper: Bool = false, wrongKey: Bool = false) async throws {
        guard state == "locked", let snapshot = selected else { throw VaultFailure("INVALID_STATE") }
        try await perform(success: "PROFILE_VERIFIED") { operation in
            var records = snapshot.records
            let keySource: Snapshot
            if wrongKey {
                guard let other = snapshots.first(where: { $0.records.id != snapshot.records.id }) else {
                    throw VaultFailure("NEEDS_TWO_PROFILES")
                }
                keySource = other
            } else { keySource = snapshot }
            var dek = try await unwrap(keySource.profileWrap, profile: keySource.records.id, purpose: 1, operation: operation)
            defer { dek.resetBytes(in: 0..<dek.count) }
            if tamper {
                records.profileRecord = String(records.profileRecord.dropLast()) + (records.profileRecord.last == "0" ? "1" : "0")
            }
            try ensure(operation)
            _ = try RustBridge.command("open", value: records, secret: dek)
        }
    }

    func prepare() throws {
        guard !busy else { throw VaultFailure("BUSY") }
        do {
            guard let id = try RustBridge.command("prepare", arguments: ["now": clock()])["requestId"] as? String else {
                throw VaultFailure("INTERNAL_ERROR")
            }
            requestID = id
            syncState()
            record("REQUEST_PREPARED")
        } catch { record(Self.classify(error)); throw error }
    }

    func verify(request: String? = nil) async throws {
        guard let snapshot = selected, let id = request ?? requestID else { throw VaultFailure("INVALID_STATE") }
        try await perform(success: "PROBE_VERIFIED") { operation in
            requestID = nil
            _ = try RustBridge.command("begin", arguments: ["requestId": id, "now": clock()])
            var dek = try await unwrap(snapshot.signingWrap, profile: snapshot.records.id, purpose: 2, operation: operation)
            defer { dek.resetBytes(in: 0..<dek.count) }
            try ensure(operation)
            _ = try RustBridge.command("finish", arguments: ["now": clock()], secret: dek)
        }
    }

    func deleteSigningKey() throws {
        guard !busy, let snapshot = selected else { throw VaultFailure("INVALID_STATE") }
        cancel()
        try adapter.delete(profile: snapshot.records.id, purpose: 2)
        record("SIGNING_KEY_DELETED")
    }

    func showError(_ error: Error) { record(Self.classify(error)) }

    static func classify(_ error: Error?) -> String {
        if let failure = error as? VaultFailure { return failure.code }
        let error = error as NSError?
        guard let error else { return "AUTH_FAILED" }
        if error.domain == LAError.errorDomain, let code = LAError.Code(rawValue: error.code) {
            switch code {
            case .biometryNotEnrolled: return "NOT_ENROLLED"
            case .biometryNotAvailable: return "UNSUPPORTED"
            case .biometryLockout: return "LOCKOUT"
            case .userCancel, .appCancel, .systemCancel: return "CANCELLED"
            case .passcodeNotSet: return "PASSCODE_NOT_SET"
            case .authenticationFailed: return "AUTH_FAILED"
            default: return "AUTH_FAILED"
            }
        }
        // Do not expose OS exception descriptions, key handles, or cryptographic data.
        return "OPERATION_FAILED"
    }
}
