# vault 作業指針

- 現在は削除予定の Chrome 拡張 PoC のみ。コード・依存・lockfile・テストは `prototypes/chrome-extension/` に閉じる。
- 製品用 crate / SDK / 公開 API をここから自動的に作らない。
- 根拠はユーザー指示と `../vault-docs/docs/prototypes/chrome-extension-implementation.md`。配置は今回のユーザー指示を優先する。
- 暗号・鍵操作・復号平文は Rust/WASM、WebAuthn と IndexedDB は TypeScript。JS へ DEK や平文を返さない。
- PRF 出力やその hash、DEK、検証平文、Credential ID をログ・例外・スクリーンショットに含めない。
- mock / virtual authenticator の成功と実機の成功を区別する。実認証器の PRF・UV・毎回認証は手動確認が必要。
- 変更後は対象ディレクトリで `npm run check`、`npm test`、`npm run build`。ブラウザが利用可能なら `npm run test:browser` も実行する。
- 実行しなかった検証と理由を報告する。ユーザー指示なく commit / push / publish しない。
