# Fall back to temp_dir for biome temp files

- Status: accepted
- Date: 2026-02-09

## Context and Problem Statement

biome チェック時、対象ファイルの `biome.json` を継承するため、一時ファイルを対象ファイルと同じディレクトリに作成していた。親ディレクトリが存在しない場合、`create_dir_all` で作成していたが、これにより `file_path` が相対パスのとき CWD に意図しないディレクトリが作成される問題があった (#2)。

## Decision

親ディレクトリが存在するかを `is_dir()` で確認し、存在しない場合は `std::env::temp_dir()` にフォールバックする。`create_dir_all` は削除する。

## Consequences

### Positive

- ユーザーの CWD にディレクトリが作成されなくなる
- 副作用のない安全な動作になる

### Negative

- 親ディレクトリが存在しない場合、`biome.json` の継承ができなくなる（temp_dir にフォールバックするため）
- 実用上の影響は軽微：対象ファイルのディレクトリが存在しないケースは、ファイル新規作成時のみであり、その時点ではプロジェクトの `biome.json` が適用されなくても lint 結果に大きな差は出ない
