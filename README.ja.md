[English](README.md) | **日本語**

# claude-guardrails

Claude Code の PreToolCall hook 用コード品質チェッカー。外部リンターとカスタムルールを組み合わせて、コードを検証し修正提案を提供します。

## 特徴

- **oxlint 統合**（優先）: [oxc.rs](https://oxc.rs) の lint ルール（ESLint プラグイン互換）
- **biome 統合**（フォールバック）: [biomejs.dev](https://biomejs.dev) の 300 以上の lint ルール
- **カスタムルール**: 外部リンターがカバーしないセキュリティパターン（JS/TS）
- **Claude 最適化出力**: stderr に修正提案を出力

## インストール

### Homebrew（推奨）

```bash
brew install thkt/tap/guardrails
```

### リリースバイナリから

[Releases](https://github.com/thkt/claude-guardrails/releases) から最新バイナリをダウンロード:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/thkt/claude-guardrails/releases/latest/download/guardrails-aarch64-apple-darwin -o guardrails
chmod +x guardrails
mv guardrails ~/.local/bin/
```

### ソースから

> **注意**: プロジェクトディレクトリ内にクローンしないでください。ネストされた git リポジトリとして残り、プロジェクトの git 操作に干渉する可能性があります。

```bash
cd /tmp
git clone https://github.com/thkt/claude-guardrails.git
cd claude-guardrails
cargo build --release
cp target/release/guardrails ~/.local/bin/
cd .. && rm -rf claude-guardrails
```

## 使い方

### Claude Code Hook として

`~/.claude/settings.json` に追加:

```json
"PreToolUse" : [
  {
    "hooks": [
      {
        "command": "guardrails",
        "timeout": 1000,
        "type": "command"
      }
    ],
    "matcher": "Write|Edit|MultiEdit"
  }
]
```

## 要件

外部リンターを少なくとも 1 つインストール（oxlint 推奨）:

- [oxlint](https://oxc.rs) CLI（`npm i -g oxlint`）— **推奨**
- [biome](https://biomejs.dev) CLI（`brew install biome` または `npm i -g @biomejs/biome`）— フォールバック

### リンター優先順位

guardrails は **oxlint を優先**します。oxlint が利用できない場合、biome にフォールバックします。チェックごとに 1 つだけ実行されます。

| 条件                              | 使用リンター       |
| --------------------------------- | ------------------ |
| oxlint がインストール済み         | oxlint             |
| oxlint 未インストール、biome あり | biome              |
| どちらも未インストール            | カスタムルールのみ |

プロジェクト設定ファイル（`oxlintrc.json`、`biome.json`）がある場合は自動的に使用されます。

## カスタムルール

外部リンターを補完するカスタムルールは `src/rules/` を参照。

### ルール

| ルール             | 重大度   | 説明                                                    | 無効化する場面                                       |
| ------------------ | -------- | ------------------------------------------------------- | ---------------------------------------------------- |
| `sensitiveFile`    | Critical | .env、credentials.\*、\*.pem への書き込みをブロック     | 無効化不可（セキュリティ上重要）                     |
| `cryptoWeak`       | High     | MD5、SHA1、DES、RC4 の使用を検出                        | 既知の制約があるレガシーシステムの保守               |
| `sensitiveLogging` | High     | console.log 内の password/token/secret を検出           | 無効化不可（セキュリティ上重要）                     |
| `security`         | High     | XSS ベクター、安全でない API、postMessage               | 無効化不可（セキュリティ上重要）                     |
| `architecture`     | High     | レイヤー違反（例: UI がドメインをインポート）           | 小規模プロジェクト、モノリス、スクリプト             |
| `eval`             | High     | eval()、new Function()、間接的 eval                     | 無効化不可（セキュリティ上重要）                     |
| `hardcodedSecrets` | High     | ソースコード内の API キー、トークン、パスワード         | 無効化不可（セキュリティ上重要）                     |
| `openRedirect`     | High     | ユーザー制御入力による location.href/assign             | Web 以外のプロジェクト                               |
| `rawHtml`          | High     | 変数を含む HTML の文字列結合                            | Web 以外のプロジェクト                               |
| `httpResource`     | Medium   | HTTP（非 HTTPS）リソース URL                            | 開発専用の設定                                       |
| `transaction`      | Medium   | トランザクションラッパーなしの複数書き込み              | データベースを使用しないプロジェクト                 |
| `domAccess`        | Medium   | React（.tsx/.jsx）での直接 DOM 操作                     | React 以外のプロジェクト、またはバニラ JS/TS         |
| `syncIo`           | Medium   | readFileSync、writeFileSync（イベントループをブロック） | CLI ツール、ビルドスクリプト、同期のみのコンテキスト |
| `bundleSize`       | Medium   | lodash/moment のフルインポート                          | バックエンド/Node.js（バンドルサイズの懸念なし）     |
| `testAssertion`    | Medium   | expect() や assert のないテスト                         | Playwright、カスタムテストフレームワーク             |
| `flakyTest`        | Low      | テスト内の setTimeout、Math.random                      | 意図的なタイミング/ランダムネスのテスト              |
| `generatedFile`    | High     | \*.generated.\*、\*.g.ts の編集を警告                   | コード生成のないプロジェクト                         |
| `testLocation`     | Medium   | src/ ディレクトリ内のテストファイル                     | コロケーションテスト戦略（ソースと同じ場所）         |
| `naming`           | Mixed    | 命名規則（hooks、コンポーネント、型）                   | チーム/プロジェクトで異なる命名規則がある場合        |

## 終了コード

| コード | 意味                       |
| ------ | -------------------------- |
| 0      | すべてのチェックに合格     |
| 2      | 問題検出（操作をブロック） |

## 設定

プロジェクトルート（`.git/` の隣）に `.claude-guardrails.json` を配置します。すべてのフィールドはオプションで、オーバーライドしたいもののみ指定してください。

**デフォルト**（設定ファイル不要）:

- すべてのルールが有効
- `critical` と `high` の重大度でブロック

### スキーマ

```json
{
  "enabled": true,
  "rules": {
    "oxlint": true,
    "biome": true,
    "sensitiveFile": true,
    "cryptoWeak": true,
    "sensitiveLogging": true,
    "security": true,
    "architecture": true,
    "eval": true,
    "hardcodedSecrets": true,
    "openRedirect": true,
    "rawHtml": true,
    "httpResource": true,
    "transaction": true,
    "domAccess": true,
    "syncIo": true,
    "bundleSize": true,
    "testAssertion": true,
    "generatedFile": true,
    "testLocation": true,
    "naming": true,
    "flakyTest": true
  },
  "severity": {
    "blockOn": ["critical", "high"]
  }
}
```

### 設定例

**最小構成**（oxlint のみ、他はデフォルト）:

```json
{
  "rules": {
    "oxlint": true
  }
}
```

**カスタムルールのみ**（外部リンター無効）:

```json
{
  "rules": {
    "oxlint": false,
    "biome": false
  }
}
```

**バックエンド（Node.js/API）** — フロントエンド固有ルールを無効化:

```json
{
  "rules": {
    "domAccess": false,
    "bundleSize": false
  }
}
```

**すべての重大度でブロック**:

```json
{
  "severity": {
    "blockOn": ["critical", "high", "medium", "low"]
  }
}
```

**プロジェクトで guardrails を無効化**:

```json
{
  "enabled": false
}
```

### 設定の解決

設定ファイルは、対象ファイルから最も近い `.git` ディレクトリまで上方向に探索されます。`.claude-guardrails.json` が存在すればデフォルトとマージされます。

```text
project-root/          ← .git/ + .claude-guardrails.json はここ
├── src/
│   └── app.ts         ← チェック対象ファイル → 上方向に設定を探索
├── .git/
└── .claude-guardrails.json
```

## 既存リンターとの併用

lefthook、husky、lint-staged 経由で oxlint/biome をコミット時に実行している場合、guardrails のリンターチェックと重複する可能性があります。両者の目的は異なります:

| ツール            | タイミング         | 目的                           |
| ----------------- | ------------------ | ------------------------------ |
| guardrails (hook) | ファイル書き込み時 | 問題が書き込まれる前に防止     |
| lefthook / husky  | コミット時         | コード履歴に入る前の最終ゲート |

外部リンターを guardrails で無効化し、コミットフックに任せるには:

```json
{
  "rules": {
    "oxlint": false,
    "biome": false
  }
}
```

これにより guardrails のカスタムセキュリティルール（sensitiveFile、cryptoWeak 等）を有効に保ちつつ、リンターの重複チェックを回避できます。

## 既知の制限事項

### 行ベースルール（architecture、security、cryptoWeak 等）

これらのルールは `non_comment_lines()` を使用し、`/* ... */` ブロックコメントの状態を行間で追跡し、`//` 行コメントをフィルタリングします:

- **`/*` や `*/` を含む文字列リテラル**: 文字列リテラル内のコメントマーカー（例: `let s = "/* not a comment */";`）は実際のコメント境界として扱われ、まれに誤ったフィルタリングが発生する可能性があります。
- **行頭のアスタリスク**: `*` で始まる行は JSDoc の継続行として扱われます。

### スキャナーベースルール（sensitiveLogging、testAssertion）

これらのルールは行間でコメント状態を追跡する `StringScanner` を使用します:

- **JavaScript 正規表現リテラル**: `//` や `/*` を含むパターン（例: `/https:\/\//`）がコメント開始として誤認識される可能性があります。

これらのトレードオフは、偽陰性よりも偽陽性が望ましい guardrails のユースケースにおいて許容範囲です。

## ライセンス

MIT
