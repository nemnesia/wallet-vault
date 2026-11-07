# vault 作業指針

## 対象と責務

この指針は独立した実装リポジトリ `vault` 全体に適用する。隣接する `core` の指示は適用しない。

- 現在の実装は削除予定の Chrome 拡張・Android・iOS プロトタイプ。コード・依存・lockfile・テスト・生成物は各 `prototypes/` 専用ディレクトリに閉じる。
- 汎用 Rust Vault の製品実装とは区別する。製品用 crate / SDK / 公開 API をプロトタイプから自動的に作らない。
- ユーザー指定の変更範囲、`README.md`、対象の `prototypes/<platform>/README.md`、作業ツリーを確認する。必要な場合は共有の `../.agents/skills/` の該当 Skill を参照する。

## 正式資料

文書の正本は別リポジトリ `vault-docs`（隣接する `../vault-docs/`）で管理する。対象案件に対応する資料と、その資料に記録された状態を確認する。

| 種別 | 所在 |
| --- | --- |
| コンセプト | 独立した承認済み文書なし |
| 汎用 Rust Vault 要件 | `../vault-docs/docs/requirements/rust-vault.md`（2026-11-08 承認済み） |
| 汎用 Rust Vault 基本設計・設計判断 | `../vault-docs/docs/design/rust-vault.md`（2026-11-08 承認済み） |
| 統合基本設計案 | `../vault-docs/docs/design/architecture.md` |
| モバイルプロトタイプ基本設計 | `../vault-docs/docs/prototypes/mobile-design.md` |
| プロトタイプ検証計画 | `../vault-docs/docs/prototypes/authentication-adapters.md` |
| プロトタイプ実装仕様 | `../vault-docs/docs/prototypes/chrome-extension-implementation.md`、`../vault-docs/docs/prototypes/android-implementation.md`、`../vault-docs/docs/prototypes/ios-implementation.md` |
| 製品仕様 | 未作成。上記要件・基本設計の承認を、公開 API・データ形式・暗号パラメータの確定や製品実装着手の承認とみなさない |

プロトタイプの実装根拠はユーザー指示と対象の実装仕様・基本設計とする。配置はユーザー指示を優先する。
プロトタイプの Session や一回限り要求の配置を、汎用 Rust Vault の責務へ自動的に引き継がない。

## 成果物の出力先

正式文書とレビュー記録は `vault-docs` の `AGENTS.md` に従い、同リポジトリへ出力する。

| 種別 | 出力先・命名規則 |
| --- | --- |
| 実装・テスト・実装用 README | 対象の `prototypes/chrome-extension/`、`prototypes/android/`、`prototypes/ios/` 内 |
| 新規の正式文書 | `../vault-docs/docs/requirements/`、`../vault-docs/docs/design/`、製品仕様作成時は `../vault-docs/docs/specifications/`（未作成） |
| レビュー成果物 | `vault-docs` の対象文書と同じディレクトリの `<対象名>-review-<3桁連番>.md`。プロトタイプ実装レビューは `../vault-docs/docs/prototypes/` に同形式で記録 |
| プロトタイプ検証結果 | `../vault-docs/docs/prototypes/results/YYYY-MM-DD-<対象環境>.md`。機械可読の観測値は対応する `-observations.json` |
| 仕様フィードバック | 対象の `vault-docs` 文書の未決定事項・仕様への引継ぎへ、根拠・影響・未検証範囲を記録。仕様が未作成なら基本設計に記録し、実装だけで契約を確定しない |

## Change-aware validation

実際の変更範囲に対応する検証を実行する。以下の実行ディレクトリは `vault` ルートからの相対パスである。
依存・ツールチェーンの準備は対象の README に従い、未実行の検証と理由を報告する。

| 変更範囲 | 検証手順・コマンド |
| --- | --- |
| 文書のみ | 変更した文書の Markdown、相対リンク、参照先・出典、文書間整合を確認。ルートで `git diff --check` と `git status --short` |
| エージェント指示・スキルのみ | 指示内の資料・出力先・コマンドを実在する文書、`package.json`、スクリプトと照合。共有 Skill を参照する場合は `SKILL.md` と同梱資料への参照を確認。ルートで `git diff --check` と `git status --short` |
| Chrome 実装・テスト | `prototypes/chrome-extension/` で `npm run check`、`npm test`、`npm run build`。ブラウザ環境が利用可能なら `npm run test:browser`。Node.js/npm、Rust、wasm-pack、WASM target が必要 |
| Android 実装・テスト | `prototypes/android/` で `npm run check`、`npm test`、`npm run build`。JNI 接続と APK 生成を確認。Node.js/npm、Rust、JDK、Android SDK/NDK と対象 Rust target が必要 |
| iOS 実装・テスト | `prototypes/ios/` で `npm run check`、`npm test`、`npm run build`。macOS、Xcode、Swift、Rust、対象 iOS target、Node.js が必要。起動済み Simulator で必要に応じて `npm run test:simulator -- <UDID>`、`npm run test:biometrics -- <UDID>` を順に実行 |
| ビルド・配布・CI | 対象の `package.json`、ビルドスクリプト、README に従い、上記の該当ビルドと生成物の配置・同梱内容を確認。製品の配布・公開手順は未定義 |

文書・指示のみの変更では実装のビルド・テストを実行しない。未追跡ファイルは内容も直接確認する。
mock / virtual authenticator / emulator / Simulator と実機の結果を区別する。
Chrome 実認証器の PRF・UV・毎回認証、Android 実機の鍵保護・認証強制、iOS 実機の Secure Enclave・毎回認証・失効は別途手動確認が必要。
APK 生成、Swift 型チェック、模擬認証の成功を実機検証の成功扱いにしない。

## プロジェクト固有のルール

- Chrome ではレコード暗号は Rust/WASM、WebAuthn と IndexedDB は TypeScript。Android では OS 鍵操作は Kotlin Adapter、レコード暗号・Session は Native Rust。iOS は Swift Adapter と C ABI 経由の Rust を用い、Simulator のソフトウェア鍵と実機の Secure Enclave 候補を区別する。iOS の React Native 接続は未実装。
- JS へ DEK や平文を返さない。PRF 出力やその hash、DEK、検証平文、Credential ID、OS 保護鍵、Mnemonic、秘密鍵、Recovery Key をログ・例外・スクリーンショット・結果資料に含めない。
- プロトタイプ撤去時は、結果・制約を製品仕様へ引き継いだことと参照切れを確認する。
- 既存の変更を上書き・取消ししない。ユーザーの明示指示なく commit / push / tag / publish / remote 変更を行わない。
- 完了時は変更ファイル、確認内容、未実行の検証と理由を簡潔に報告する。
