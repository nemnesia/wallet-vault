#if targetEnvironment(simulator)
import Foundation
import UIKit

@MainActor
private final class InjectedBiometrics: BiometricAuthenticating {
    enum Outcome { case pass, fail, cancel, pause }
    var outcome = Outcome.pass
    var calls = 0
    var suspended: CheckedContinuation<Void, Error>?

    func authenticate(_ context: AuthenticationContext) async throws {
        calls += 1
        let next = outcome
        outcome = .pass
        switch next {
        case .pass: return
        case .fail: throw VaultFailure("AUTH_FAILED")
        case .cancel: throw VaultFailure("CANCELLED")
        case .pause:
            try await withCheckedThrowingContinuation { suspended = $0 }
        }
    }

    func resume() {
        suspended?.resume()
        suspended = nil
    }
}

// Simulator-only harness. Authentication is explicitly injected; real CryptoKit,
// Keychain, snapshot storage, Swift/C ABI and Rust operations still execute.
@MainActor
enum IntegrationTests {
    static func run(phase: String) async -> String {
        var observations: [[String: String]] = []
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let reportURL = documents.appendingPathComponent("ios-integration-\(phase).json")
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let root = base.appendingPathComponent("VaultIOS-Integration-v1", isDirectory: true)
        let auth = InjectedBiometrics()
        var tick: UInt64 = 1000
        let vault = VaultController(backend: .softwareSimulator, root: root,
            namespace: "integration-v1", authenticator: auth, clock: { tick })
        func check(_ condition: Bool, _ name: String) throws {
            observations.append(["case": name, "result": condition ? "PASS" : "FAIL"])
            if !condition { throw VaultFailure("TEST_FAILED") }
        }
        func rejects(_ expected: String, _ body: () async throws -> Void) async throws {
            do { try await body(); throw VaultFailure("UNEXPECTED_SUCCESS") }
            catch { try check(VaultController.classify(error) == expected, "reject_" + expected) }
        }
        func waitForSuspension() async throws {
            for _ in 0..<300 {
                if auth.suspended != nil { return }
                try await Task.sleep(for: .milliseconds(10))
            }
            throw VaultFailure("TEST_TIMEOUT")
        }
        do {
            if phase == "roundtrip" {
                // A new dedicated installation should start empty. A repeated run
                // preserves old test snapshots rather than deleting user data.
                let before = vault.snapshots.count
                try await vault.register(label: "Simulator integration")
                try check(vault.state == "locked" && vault.snapshots.count == before + 1, "register_save_locked")
                let firstID = vault.selectedID!
                let original = vault.selected!
                var badWrap = original.profileWrap
                badWrap.sealed[badWrap.sealed.count - 1] ^= 1
                try await rejects("INTEGRITY_FAILED") {
                    _ = try vault.adapter.unwrapSync(badWrap, profile: firstID, purpose: 1, context: AuthenticationContext())
                }
                try await rejects("INTEGRITY_FAILED") {
                    _ = try vault.adapter.unwrapSync(original.profileWrap, profile: firstID, purpose: 2, context: AuthenticationContext())
                }
                let differentBackend = KeyWrap(backend: .secureEnclave,
                    ephemeralPublicKey: original.profileWrap.ephemeralPublicKey,
                    salt: original.profileWrap.salt, sealed: original.profileWrap.sealed)
                try await rejects("INVALID_INPUT") {
                    _ = try vault.adapter.unwrapSync(differentBackend, profile: firstID, purpose: 1, context: AuthenticationContext())
                }
                try await rejects("PROFILE_EXISTS") { try vault.store.save(original) }
                let corruptionRoot = root.appendingPathComponent("corruption-" + UUID().uuidString)
                let corruptionStore = try SnapshotStore(root: corruptionRoot, backend: .softwareSimulator)
                try corruptionStore.save(original)
                let corruptURL = corruptionStore.directory.appendingPathComponent(firstID + ".json")
                try Data("{}".utf8).write(to: corruptURL, options: .atomic)
                do {
                    _ = try corruptionStore.load()
                    throw VaultFailure("UNEXPECTED_SUCCESS")
                } catch {
                    try check(!(error is VaultFailure), "corrupt_snapshot_rejected")
                }
                try FileManager.default.removeItem(at: corruptionRoot)
                try await vault.register(label: "Second integration")
                let secondID = vault.selectedID!
                vault.select(firstID)
                let committed = vault.snapshots.count
                try await rejects("STORAGE_FAILED") { try await vault.register(label: "Abort integration", abort: true) }
                vault.reload()
                try check(vault.snapshots.count == committed && vault.selectedID == firstID, "abort_preserves_committed_profiles")
                try await rejects("INTEGRITY_FAILED") { try await vault.open(tamper: true) }
                try await rejects("INTEGRITY_FAILED") { try await vault.open(wrongKey: true) }
                try check(vault.state == "locked", "integrity_failures_keep_locked")
                auth.outcome = .cancel
                try await rejects("CANCELLED") { try await vault.open() }
                auth.outcome = .fail
                try await rejects("AUTH_FAILED") { try await vault.open() }
                try check(vault.state == "locked", "auth_failures_keep_locked")
                auth.outcome = .cancel
                try await rejects("CANCELLED") { try await vault.register(label: "Cancelled registration") }
                vault.reload()
                try check(vault.snapshots.count == committed, "registration_cancel_does_not_publish_profile")
                try await vault.open()
                try check(vault.state == "unlocked", "swift_c_rust_profile_decrypt")
                for number in 1...2 {
                    try vault.prepare()
                    let request = vault.requestID!
                    let calls = auth.calls
                    try await vault.verify()
                    try check(vault.result == "PROBE_VERIFIED" && vault.state == "unlocked" && auth.calls == calls + 1,
                        "fresh_auth_and_signing_probe_\(number)")
                    try await rejects("INVALID_STATE") { try await vault.verify(request: request) }
                }
                try vault.prepare()
                tick += 60000
                try await rejects("EXPIRED") { try await vault.verify() }
                try check(vault.state == "unlocked" && vault.requestID == nil, "expiry_consumes_request_keeps_profile")
                try vault.prepare()
                auth.outcome = .cancel
                try await rejects("CANCELLED") { try await vault.verify() }
                try check(vault.state == "unlocked" && vault.requestID == nil, "signing_cancel_keeps_profile")

                // Hold the authentication callback, lock, start a replacement
                // operation, then deliver the old success to the real controller.
                vault.lock()
                auth.outcome = .pause
                let stale = Task { @MainActor in try await vault.open() }
                try await waitForSuspension()
                try await rejects("BUSY") { try await vault.open() }
                vault.lock(background: true)
                try await vault.open()
                auth.resume()
                _ = try? await stale.value
                try check(vault.state == "unlocked" && vault.result == "PROFILE_VERIFIED", "late_callback_cannot_alter_replacement")

                try vault.prepare()
                auth.outcome = .pause
                let background = Task { @MainActor in try await vault.verify() }
                try await waitForSuspension()
                vault.lock(background: true)
                auth.resume()
                _ = try? await background.value
                try check(vault.state == "locked" && vault.requestID == nil, "controller_background_handler_discards_session_and_late_signing_result")

                auth.outcome = .pause
                let expiring = Task { @MainActor in try await vault.open() }
                try await waitForSuspension()
                tick += 60000
                auth.resume()
                try await rejects("EXPIRED") { try await expiring.value }
                try check(vault.state == "locked", "auth_deadline_rechecked_after_callback")

                try await vault.open()
                try vault.deleteSigningKey()
                try vault.prepare()
                try await rejects("KEY_INVALIDATED") { try await vault.verify() }
                try check(vault.state == "unlocked", "missing_signing_key_keeps_profile")
                vault.lock()
                try await vault.open()
                try check(vault.state == "unlocked", "profile_key_independent_after_signing_delete")
                vault.lock()

                // Keep the second intact Profile for a separate process launch.
                try Data(secondID.utf8).write(to: root.appendingPathComponent("restart-profile"), options: .atomic)
            } else if phase == "restart" {
                try check(vault.state == "locked" && vault.requestID == nil, "new_process_starts_locked_without_request")
                let id = try String(contentsOf: root.appendingPathComponent("restart-profile"), encoding: .utf8)
                vault.select(id)
                try check(vault.selectedID == id, "committed_snapshot_survives_process_restart")
                try await vault.open()
                try vault.prepare()
                try await vault.verify()
                try check(vault.result == "PROBE_VERIFIED", "keychain_and_rust_roundtrip_after_process_restart")
                vault.lock()
            } else { throw VaultFailure("INVALID_PHASE") }
        } catch {
            observations.append(["case": "suite", "result": "FAIL", "code": VaultController.classify(error)])
        }
        let passed = !observations.contains { $0["result"] != "PASS" }
        let args = ProcessInfo.processInfo.arguments
        let runIndex = args.firstIndex(of: "--test-run")
        let runID = runIndex.flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } ?? "manual"
        let report: [String: Any] = ["schema": 1, "phase": phase, "runId": runID,
            "environment": "iOS \(UIDevice.current.systemVersion) / Simulator", "authentication": "TEST_DOUBLE",
            "backend": "SOFTWARE_SIMULATOR", "realBiometricAuthenticationTested": false,
            "secureEnclaveProtectionTested": false, "result": passed ? "PASS" : "FAIL", "observations": observations]
        do {
            try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
            try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]).write(to: reportURL, options: .atomic)
        } catch { return "TEST_DOUBLE / REPORT_WRITE_FAILED" }
        return "TEST_DOUBLE / \(phase) / \(passed ? "PASS" : "FAIL")"
    }
}
#endif
