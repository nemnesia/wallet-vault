# vault 作業指針

## 対象と責務

この指針は独立した実装リポジトリ `vault` 全体に適用する。隣接する `core` の指示は適用しない。

- 既存プロトタイプは削除予定の Chrome 拡張・Android・iOS。コード・依存・lockfile・テスト・生成物は各 `prototypes/` 専用ディレクトリに閉じる。
- 汎用 Rust Vault の製品実装とは区別する。製品用 crate / SDK / 公開 API をプロトタイプから自動的に作らない。
- Vault は汎用バイト列の暗号・鍵管理を担う。Core と相互依存せず、Profile / Account / Session、chain / network、署名意味論、保存 I/O は上位に置く。
- ルートと本リポジトリの Git 状態、ユーザー指定の変更範囲、`README.md`、対象実装の README・manifest・lockfile を確認する。
- 製品の実装・修正は [implement-author](../.agents/skills/implement-author/SKILL.md)、実装レビューは [implement-review](../.agents/skills/implement-review/SKILL.md) に従う。

## 正式資料

文書の正本は別リポジトリ `vault-docs`（隣接する `../vault-docs/`）で管理する。対象案件に対応する資料と、その資料に記録された状態を確認する。

| 種別 | 所在 |
| --- | --- |
| コンセプト | 独立した承認済み文書なし |
| 汎用 Rust Vault 要件 | [要件本文](../vault-docs/docs/requirements/rust-vault.md)、[要件レビュー002](../vault-docs/docs/requirements/rust-vault-review-002.md) |
| 汎用 Rust Vault 基本設計・設計判断 | [基本設計本文](../vault-docs/docs/design/rust-vault.md)、[基本設計レビュー002](../vault-docs/docs/design/rust-vault-review-002.md) |
| 統合基本設計案 | `../vault-docs/docs/design/architecture.md` |
| モバイルプロトタイプ基本設計 | `../vault-docs/docs/prototypes/mobile-design.md` |
| プロトタイプ検証計画 | `../vault-docs/docs/prototypes/authentication-adapters.md` |
| プロトタイプ実装仕様 | `../vault-docs/docs/prototypes/chrome-extension-implementation.md`、`../vault-docs/docs/prototypes/android-implementation.md`、`../vault-docs/docs/prototypes/ios-implementation.md` |
| 製品仕様 | [汎用 Rust Vault 詳細仕様](../vault-docs/docs/specifications/rust-vault.md)、[詳細仕様再レビュー006](../vault-docs/docs/specifications/rust-vault-review-006.md)。現行本文の承認・変更記録と実装依頼の範囲を確認する |
| SDK 統合契約 | [Wallet / Vault 統合契約](../vault-docs/docs/specifications/wallet-vault-integration.md)。Vault 本体の仕様承認と区別し、本文の状態を確認する |
| 製品成立性の実測計画 | [実測計画](../vault-docs/docs/prototypes/vault-product-validation.md)。計画と実施結果を区別する |

承認状態と変更判断は各正式資料の現行本文・承認記録・対応レビューで確認する。基準版の承認やレビューの READY だけで、後続改訂や製品の正式対応を承認済みにしない。

## 製品実装の開始手順

1. 対象操作に必要な詳細仕様 §2〜9、試験条件 §12・12.1、開始条件 §13 と承認・変更記録 §14 を確認し、要件・基本設計へ追跡する。
2. 実装依頼の範囲を確認し、製品用 manifest と README を下表の配置で用意する。API・形式・暗号パラメータは仕様に従い、プロトタイプから契約を引き継がない。
3. OS 鍵方式は現行仕様 §6.5・S-10 に従う。実機成立性と KDF の実運用適合・安全な予算は実測で判断し、未実測でも固定契約の実装・適合試験と区別して扱う。新たな未決定事項や資料間競合は該当部分の実装を保留し、正本へフィードバックする。
4. 実装した範囲を検証し、未実装操作・未対応環境・実機未検証を README と完了報告に明記する。今回の指示整備自体は実装コードの作成や配布・公開の依頼ではない。

プロトタイプの実装根拠はユーザー指示と対象の実装仕様・基本設計とする。配置はユーザー指示を優先する。
プロトタイプの Session や一回限り要求の配置を、汎用 Rust Vault の責務へ自動的に引き継がない。

## 成果物の出力先

正式文書とレビュー記録は `vault-docs` の `AGENTS.md` に従い、同リポジトリへ出力する。

| 種別 | 出力先・命名規則 |
| --- | --- |
| 製品Rust実装・テスト | `rust/`。プロトタイプと独立したcrateで管理し、製品全体の完成・実機対応と区別する |
| 製品の Native / WASM 境界・OS Adapter | 製品 Rust の境界は `rust/` 内、OS 固有実装は `adapters/android/`、`adapters/ios/`。対応するテスト・生成元・ビルド手順を同じ対象内に置く |
| 製品の利用・検証手順 | ルート `README.md` と各製品ディレクトリの README。実装追加時に前提・正確なコマンド・生成先を記録する |
| プロトタイプ実装・テスト・実装用 README | 対象の `prototypes/chrome-extension/`、`prototypes/android/`、`prototypes/ios/` 内 |
| 新規の正式文書 | `../vault-docs/docs/requirements/`、`../vault-docs/docs/design/`、製品仕様は `../vault-docs/docs/specifications/` |
| レビュー成果物 | `vault-docs` の対象文書と同じディレクトリの `<対象名>-review-<3桁連番>.md`。プロトタイプ実装レビューは `../vault-docs/docs/prototypes/` に同形式で記録 |
| プロトタイプ検証結果 | `../vault-docs/docs/prototypes/results/YYYY-MM-DD-<対象環境>.md`。機械可読の観測値は対応する `-observations.json` |
| 仕様フィードバック | 対象の `vault-docs` 文書の未決定事項・仕様への引継ぎへ、根拠・影響・未検証範囲を記録。仕様が未作成なら基本設計に記録し、実装だけで契約を確定しない |

## Change-aware validation

実際の変更範囲に対応する検証を実行する。以下の実行ディレクトリは `vault` ルートからの相対パスである。
依存・ツールチェーンの準備は対象の README に従い、未実行の検証と理由を報告する。
製品用の下記ディレクトリ・manifest・検証スクリプトは今後の実装時の配置であり、現時点で存在・実行可能とは扱わない。
製品 crate 作成時は Rust のバージョン・必要 target・feature と lockfile を記録する。境界・Adapter の検証は実装時に具体的なコマンドを README に定義し、本表を更新する。

| 変更範囲 | 検証手順・コマンド |
| --- | --- |
| 文書のみ | 変更した文書の Markdown、相対リンク、参照先・出典、文書間整合を確認。ルートで `git diff --check` と `git status --short` |
| エージェント指示・スキルのみ | 指示内の資料・出力先・コマンドを実在する文書、`package.json`、スクリプトと照合。共有 Skill を参照する場合は `SKILL.md` と同梱資料への参照を確認。ルートで `git diff --check` と `git status --short` |
| 製品 Rust | `rust/` に manifest・lockfile を作成後、同ディレクトリで `cargo fmt -- --check`、`cargo clippy --all-targets --locked -- -D warnings`、`cargo test --locked`。詳細仕様 §12・12.1 の対象試験を含める |
| 製品の Native C ABI | 上記に加え、`rust/` の README に定める header compile と runtime 試験。所有権・専用 free・panic 境界・取消・不正入力を確認 |
| 製品の WASM | 上記に加え、`rust/` で `cargo check --locked --target wasm32-unknown-unknown`。対象 feature は manifest / README に従う。README に定める WASM ビルド・JS 境界試験と Rust / Native との固定ベクトル一致を確認。Rust target と生成・試験ツールが必要 |
| 製品の OS Adapter | 対象の `adapters/<platform>/` の README に従いビルド・境界試験。Android SDK/NDK・JDK、iOS は macOS・Xcode 等が必要。認証と鍵操作・取消・失効・保護要件は実機で別途確認 |
| Chrome プロトタイプ実装・テスト | `prototypes/chrome-extension/` で `npm run check`、`npm test`、`npm run build`。ブラウザ環境が利用可能なら `npm run test:browser`。Node.js/npm、Rust、wasm-pack、WASM target が必要 |
| Android プロトタイプ実装・テスト | `prototypes/android/` で `npm run check`、`npm test`、`npm run build`。JNI 接続と APK 生成を確認。Node.js/npm、Rust、JDK、Android SDK/NDK と対象 Rust target が必要 |
| iOS プロトタイプ実装・テスト | `prototypes/ios/` で `npm run check`、`npm test`、`npm run build`。macOS、Xcode、Swift、Rust、対象 iOS target、Node.js が必要。起動済み Simulator で必要に応じて `npm run test:simulator -- <UDID>`、`npm run test:biometrics -- <UDID>` を順に実行 |
| ビルド・配布・CI | 対象の manifest、ビルドスクリプト、README に従い、上記の該当ビルドと生成物の配置・同梱内容を確認。製品の配布・公開手順は未定義 |

文書・指示のみの変更では実装のビルド・テストを実行しない。未追跡ファイルは内容も直接確認する。
mock / virtual authenticator / emulator / Simulator と実機の結果を区別する。
Chrome 実認証器の PRF・UV・毎回認証、Android 実機の鍵保護・認証強制、iOS 実機の Secure Enclave・毎回認証・失効は別途手動確認が必要。
APK 生成、Swift 型チェック、模擬認証の成功を実機検証の成功扱いにしない。

## プロジェクト固有のルール

- 以下はプロトタイプ固有の構成であり、製品の責務を決める根拠にしない。Chrome ではレコード暗号は Rust/WASM、WebAuthn と IndexedDB は TypeScript。Android では OS 鍵操作は Kotlin Adapter、レコード暗号・Session は Native Rust。iOS は Swift Adapter と C ABI 経由の Rust を用い、Simulator のソフトウェア鍵と実機の Secure Enclave 候補を区別する。iOS の React Native 接続は未実装。
- 製品の秘密情報境界は詳細仕様 §2・4・10 に従う。Native の DEK・署名秘密値は Native / Rust 内に限定し、汎用 Decrypt・秘密を含む段階 API を React Native 等の JS へ転送しない。WASM は仕様で許容する PRF 出力・復号平文の JS 受渡しを扱い、JS / FFI / GC の全コピーの消去を保証しない。汎用 DEK export は設けない。プロトタイプでは引き続き JS へ DEK や平文を返さない。
- PRF 出力やその hash、DEK、検証平文、Credential ID、OS 保護鍵、Mnemonic、秘密鍵、Recovery Key をログ・例外・スクリーンショット・結果資料に含めない。公開テスト専用の既知値は、詳細仕様 §12 と文書側指示に従い、非本番・出典または生成手順・照合対象を明記する場合に限って fixture 等に使える。実ユーザー・実機生成の秘密値や通常ログへの出力は含まない。
- 固定ベクトル、改ざん・異文脈・不正形式、SR-001 の別 Recovery Key、更新の不変部分、保存失敗、取消後公開、資源予約と解放を仕様へ追跡して検証する。mock の成功を OS 認証や実機の成立証明にしない。
- プロトタイプ撤去時は、結果・制約を製品仕様へ引き継いだことと参照切れを確認する。
- 既存の変更を上書き・取消ししない。ユーザーの明示指示なく commit / push / tag / publish / remote 変更を行わない。
- 完了時は変更ファイル、確認内容、未実行の検証と理由を簡潔に報告する。
