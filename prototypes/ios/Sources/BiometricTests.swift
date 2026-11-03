#if targetEnvironment(simulator)
import Foundation
import UIKit

@MainActor
private final class ObservedSystemBiometrics: BiometricAuthenticating {
    var calls = 0
    var intent = "match"
    let progress: (Int, String, String) -> Void
    init(progress: @escaping (Int, String, String) -> Void) { self.progress = progress }
    func authenticate(_ context: AuthenticationContext) async throws {
        calls += 1
        let call = calls
        progress(call, "waiting", intent)
        do {
            try await SystemBiometrics().authenticate(context)
            progress(call, "completed", intent)
        } catch {
            progress(call, "rejected", intent)
            throw error
        }
    }
}

@MainActor
enum BiometricTests {
    static func run(phase: String, runID: String) async -> String {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let reportURL = documents.appendingPathComponent("ios-biometric-\(phase).json")
        let progressURL = documents.appendingPathComponent("ios-biometric-progress.json")
        try? FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        let auth = ObservedSystemBiometrics { call, status, intent in
            let value: [String: Any] = ["runId": runID, "call": call, "status": status, "intent": intent]
            if let data = try? JSONSerialization.data(withJSONObject: value) { try? data.write(to: progressURL, options: .atomic) }
        }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let vault = VaultController(backend: .softwareSimulator,
            root: base.appendingPathComponent("VaultIOS-Biometrics-v1"), namespace: "biometrics-v1", authenticator: auth)
        var observations: [[String: String]] = []
        func check(_ condition: Bool, _ name: String) throws {
            observations.append(["case": name, "result": condition ? "PASS" : "FAIL"])
            if !condition { throw VaultFailure("TEST_FAILED") }
        }
        func awaitCall(_ after: Int) async throws {
            for _ in 0..<300 {
                if auth.calls > after { return }
                try await Task.sleep(for: .milliseconds(10))
            }
            throw VaultFailure("TEST_TIMEOUT")
        }
        do {
            if phase == "unenrolled" {
                let before = vault.snapshots.count
                do {
                    try await vault.register(label: "Unenrolled simulator")
                    throw VaultFailure("UNEXPECTED_SUCCESS")
                } catch { try check(VaultController.classify(error) == "NOT_ENROLLED", "local_authentication_unenrolled_rejected") }
                try check(vault.state == "locked" && vault.snapshots.count == before, "unenrolled_does_not_save_profile")
            } else if phase == "enrolled" {
                try await vault.register(label: "Face ID simulator")
                try check(vault.state == "locked" && auth.calls == 2, "two_simulated_authentications_before_save")
                try await vault.open()
                try check(vault.state == "unlocked" && auth.calls == 3, "simulated_face_id_profile_decrypt")
                for number in 1...2 {
                    try vault.prepare()
                    try await vault.verify()
                    try check(vault.result == "PROBE_VERIFIED" && auth.calls == 3 + number,
                        "separate_simulated_face_id_signing_probe_\(number)")
                }
                vault.lock()
                auth.intent = "nonmatch"
                let previous = auth.calls
                let mismatch = Task { @MainActor in try await vault.open() }
                try await awaitCall(previous)
                try await Task.sleep(for: .seconds(3))
                let stillLocked = vault.state == "locked"
                vault.cancel()
                do { try await mismatch.value; throw VaultFailure("UNEXPECTED_SUCCESS") }
                catch {
                    let code = VaultController.classify(error)
                    try check(stillLocked && ["CANCELLED", "AUTH_FAILED"].contains(code), "nonmatching_face_never_unlocks")
                }
                auth.intent = "hold"
                let beforeCancel = auth.calls
                let cancelled = Task { @MainActor in try await vault.open() }
                try await awaitCall(beforeCancel)
                try await Task.sleep(for: .milliseconds(700))
                vault.cancel()
                do { try await cancelled.value; throw VaultFailure("UNEXPECTED_SUCCESS") }
                catch { try check(VaultController.classify(error) == "CANCELLED" && vault.state == "locked", "real_la_context_invalidation_cancels") }
                auth.intent = "match"
                try await vault.open()
                try check(vault.state == "unlocked", "new_context_works_after_cancel")
                vault.lock()
            } else { throw VaultFailure("INVALID_PHASE") }
        } catch {
            observations.append(["case": "suite", "result": "FAIL", "code": VaultController.classify(error)])
            vault.lock()
        }
        let passed = !observations.contains { $0["result"] != "PASS" }
        let report: [String: Any] = ["schema": 1, "phase": phase, "runId": runID,
            "environment": "iOS \(UIDevice.current.systemVersion) / Simulator",
            "authentication": "LOCAL_AUTHENTICATION_SIMULATED_FACE_ID", "backend": "SOFTWARE_SIMULATOR",
            "authenticationCalls": auth.calls, "realBiometricAuthenticationTested": false,
            "secureEnclaveProtectionTested": false, "result": passed ? "PASS" : "FAIL", "observations": observations]
        do {
            try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]).write(to: reportURL, options: .atomic)
        } catch { return "LA_SIMULATED / REPORT_WRITE_FAILED" }
        return "LA_SIMULATED / \(phase) / \(passed ? "PASS" : "FAIL")"
    }
}
#endif
