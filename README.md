# Vault

現在は [Chrome 拡張プロトタイプ](prototypes/chrome-extension/README.md)と
[Android プロトタイプ](prototypes/android/README.md)を置いています。
ChromeではPasskey PRFとRust/WASM、AndroidではKeystore・BiometricPromptとNative Rustによる
暗号化・保存・再認証での復号を検証します。

プロトタイプは最終的に削除する予定です。実装・依存・テストは
各 `prototypes/` 専用ディレクトリ内にまとめており、対象ディレクトリを削除して撤去できます。
製品実装・移行互換性・復旧機能は提供していません。
