import CryptoKit
import SwiftUI

@main
struct VaultSimulatorApp: App {
    @StateObject private var vault: VaultController
    @Environment(\.scenePhase) private var phase
    @State private var label = "iPhone 検証"
    @State private var abortSave = false
    @State private var confirmDelete = false
    @State private var integrationSummary: String?

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        #if targetEnvironment(simulator)
        let backend = Backend.softwareSimulator
        #else
        let backend = Backend.secureEnclave
        #endif
        _vault = StateObject(wrappedValue: VaultController(backend: backend,
            root: base.appendingPathComponent("VaultIOS-v1", isDirectory: true)))
    }

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("検証環境") {
                        Text("iOS \(UIDevice.current.systemVersion)")
                        Text(vault.biometry)
                        #if targetEnvironment(simulator)
                        Text("Simulator の補助検証です。ソフトウェア鍵は非エクスポート鍵ではありません。実機の認証強制・鍵保護は別途確認します。")
                        Picker("鍵モード", selection: Binding(get: { vault.backend }, set: { vault.switchBackend($0) })) {
                            ForEach(Backend.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }.disabled(vault.busy)
                        #else
                        Text("SECURE_ENCLAVE / 実機検証候補")
                        #endif
                        Text("Secure Enclave API: \(SecureEnclave.isAvailable ? "available（操作成立は別判定）" : "UNSUPPORTED")")
                        Text("SwiftUI → Native → Rust。Signing は検証データの照合です。")
                        if let integrationSummary { Text(integrationSummary) }
                    }
                    Section("Profile") {
                        TextField("検証用の表示名", text: $label)
                        Toggle("保存途中 abort を注入", isOn: $abortSave)
                        Button("認証して登録・保存") { run { try await vault.register(label: label, abort: abortSave) } }
                            .disabled(vault.busy || vault.state != "locked")
                        Picker("保存済み Profile", selection: Binding(get: { vault.selectedID ?? "" }, set: { vault.select($0) })) {
                            Text("未選択").tag("")
                            ForEach(vault.snapshots, id: \.records.id) { snapshot in
                                Text("\(snapshot.records.label) / \(snapshot.records.id.prefix(8))").tag(snapshot.records.id)
                            }
                        }.disabled(vault.busy)
                        Button("再認証して Profile を復号") { run { try await vault.open() } }
                            .disabled(vault.busy || vault.selected == nil || vault.state != "locked")
                    }
                    Section("一回限りの照合") {
                        Button("要求を準備") { do { try vault.prepare() } catch { vault.showError(error) } }
                            .disabled(vault.busy || vault.state != "unlocked")
                        Button("再認証して Signing データを照合") { run { try await vault.verify() } }
                            .disabled(vault.busy || vault.requestID == nil)
                        Button("認証・要求を取消", role: .destructive) { vault.cancel() }
                            .disabled(!vault.busy && vault.requestID == nil)
                        Button("lock") { vault.lock() }
                        Button("環境を再確認") { vault.refreshBiometry() }.disabled(vault.busy)
                    }
                    Section("異常系（保存データは変更しません）") {
                        Button("改ざんコピーを拒否するか確認") { run { try await vault.open(tamper: true) } }
                            .disabled(vault.busy || vault.state != "locked" || vault.selected == nil)
                        Button("別 Profile の鍵を拒否するか確認") { run { try await vault.open(wrongKey: true) } }
                            .disabled(vault.busy || vault.state != "locked" || vault.snapshots.count < 2)
                        Button("検証用 Signing 鍵参照を削除", role: .destructive) { confirmDelete = true }
                            .disabled(vault.busy || vault.selected == nil)
                    }
                    Section("非秘密の結果") {
                        Text("state: \(vault.state)")
                        Text(vault.result).font(.system(.body, design: .monospaced))
                        ShareLink("結果を共有", item: "\(vault.backend.rawValue) / iOS \(UIDevice.current.systemVersion)\nstate=\(vault.state)\n" + vault.events.joined(separator: "\n"))
                        ForEach(Array(vault.events.enumerated()), id: \.offset) { _, event in
                            Text(event).font(.system(.caption, design: .monospaced))
                        }
                    }
                }
                .navigationTitle("Vault1 iPhone PoC")
                .confirmationDialog("この Profile の Signing 鍵参照を Keychain から削除します。復旧できません。", isPresented: $confirmDelete) {
                    Button("Signing 鍵参照を削除", role: .destructive) {
                        do { try vault.deleteSigningKey() } catch { vault.showError(error) }
                    }
                }
                .onChange(of: phase) { _, next in
                    if next == .background { vault.lock(background: true) }
                    if next == .active { vault.refreshBiometry() }
                }
                .task {
                    #if targetEnvironment(simulator)
                    if let index = ProcessInfo.processInfo.arguments.firstIndex(of: "--integration-tests"),
                       ProcessInfo.processInfo.arguments.count > index + 1 {
                        integrationSummary = await IntegrationTests.run(phase: ProcessInfo.processInfo.arguments[index + 1])
                    }
                    if let index = ProcessInfo.processInfo.arguments.firstIndex(of: "--biometric-tests"),
                       ProcessInfo.processInfo.arguments.count > index + 2 {
                        integrationSummary = await BiometricTests.run(phase: ProcessInfo.processInfo.arguments[index + 1],
                            runID: ProcessInfo.processInfo.arguments[index + 2])
                    }
                    #endif
                }
            }
        }
    }

    private func run(_ operation: @escaping @MainActor () async throws -> Void) {
        Task { @MainActor in
            do { try await operation() } catch { /* Controller owns classified operation results. */ }
        }
    }
}
