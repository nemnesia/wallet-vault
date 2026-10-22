# vault 作業指針

- 現在は削除予定の Chrome 拡張と Android PoC。コード・依存・lockfile・テストは各 `prototypes/` 専用ディレクトリに閉じる。
- 製品用 crate / SDK / 公開 API をここから自動的に作らない。
- 根拠はユーザー指示と `../vault-docs/docs/prototypes/` の対象実装仕様・基本設計。配置はユーザー指示を優先する。
- Chromeではレコード暗号はRust/WASM、WebAuthnとIndexedDBはTypeScript。AndroidではOS鍵操作はKotlin Adapter、レコード暗号・SessionはNative Rust。JSへDEKや平文を返さない。
- PRF 出力やその hash、DEK、検証平文、Credential ID をログ・例外・スクリーンショットに含めない。
- mock / virtual authenticator の成功と実機の成功を区別する。実認証器の PRF・UV・毎回認証は手動確認が必要。
- 変更後は対象ディレクトリで `npm run check`、`npm test`、`npm run build`。Chromeは利用可能なら `npm run test:browser`、AndroidはJNI・APK生成を確認し実機未接続の認証検証を成功扱いしない。
- 実行しなかった検証と理由を報告する。ユーザー指示なく commit / push / publish しない。
