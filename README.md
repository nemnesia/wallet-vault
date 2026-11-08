# Vault

[汎用 Rust Vault](rust/README.md)に、v1 の共通暗号・11操作・C ABI・WASM 境界を実装しています。
OS Adapter・Wallet SDK 統合・実機対応は未実装または未検証です。利用・検証手順と範囲は同 README を参照してください。

現在は [Chrome 拡張プロトタイプ](prototypes/chrome-extension/README.md)と
[Android プロトタイプ](prototypes/android/README.md)を置いています。
ChromeではPasskey PRFとRust/WASM、AndroidではKeystore・BiometricPromptとNative Rustによる
暗号化・保存・再認証での復号を検証します。

[iPhone Native / Rust プロトタイプ](prototypes/ios/README.md)も追加しています。
用途別の鍵ラップ・暗号化保存・再認証後の Rust 復号・一回限り照合を確認する実験用アプリです。
Simulator のソフトウェア鍵検証と、実機の Secure Enclave 検証候補を区別します。React Native は未接続です。

プロトタイプは最終的に削除する予定です。実装・依存・テストは
各 `prototypes/` 専用ディレクトリ内にまとめており、対象ディレクトリを削除して撤去できます。
これらのプロトタイプに、製品形式への移行互換性を提供していません。製品用の共通 Rust 実装と区別してください。
