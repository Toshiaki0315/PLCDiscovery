# PLC Discovery - データベース管理スクリプト

このディレクトリには、SQLiteデータベースのセットアップと管理用スクリプトが含まれています。

## スクリプト一覧

| ファイル | 説明 |
|----------|------|
| `setup_database.sh` | データベース作成（シェルスクリプト版） |
| `setup_database.py` | データベース作成（Python版） |
| `manage_database.sh` | データベース管理ツール |

## セットアップスクリプト

### シェルスクリプト版 (`setup_database.sh`)

```bash
# デフォルトパス（./plc_data.db）に作成
./scripts/setup_database.sh

# 指定したパスに作成
./scripts/setup_database.sh /path/to/database.db
```

### Python版 (`setup_database.py`)

```bash
# デフォルトパスに作成
python scripts/setup_database.py

# 指定したパスに作成
python scripts/setup_database.py /path/to/database.db

# 強制再作成（確認なし）
python scripts/setup_database.py --force ./plc_data.db

# ステータス表示
python scripts/setup_database.py --status ./plc_data.db
```

## 管理スクリプト (`manage_database.sh`)

```bash
./scripts/manage_database.sh <command> [database_path] [options]
```

### コマンド

| コマンド | 説明 | 例 |
|----------|------|-----|
| `status` | ステータスと統計情報を表示 | `manage_database.sh status ./plc_data.db` |
| `tables` | テーブル一覧と行数を表示 | `manage_database.sh tables` |
| `backup` | バックアップを作成 | `manage_database.sh backup ./plc_data.db` |
| `cleanup` | 古いデータを削除 | `manage_database.sh cleanup ./plc_data.db 7` |
| `vacuum` | データベースを最適化 | `manage_database.sh vacuum` |
| `export` | CSVにエクスポート | `manage_database.sh export ./plc_data.db` |
| `reset` | すべてのデータを削除 | `manage_database.sh reset ./plc_data.db` |
| `shell` | SQLite対話型シェル | `manage_database.sh shell` |

### 使用例

```bash
# 新しいデータベースを作成
./scripts/setup_database.sh ./plc_data.db

# PLCスキャンを実行（データベースに保存）
python plc_scanner.py --mode full --target 192.168.1.10 --database ./plc_data.db

# ステータスを確認
./scripts/manage_database.sh status ./plc_data.db

# 結果をCSVにエクスポート
./scripts/manage_database.sh export ./plc_data.db

# 30日以上前のデータを削除
./scripts/manage_database.sh cleanup ./plc_data.db 30

# データベースを最適化
./scripts/manage_database.sh vacuum ./plc_data.db
```

## データベーススキーマ

### テーブル構成

#### `plcs` - 検出されたPLC情報
| カラム | 型 | 説明 |
|--------|-----|------|
| `id` | INTEGER | 主キー |
| `ip_address` | TEXT | IPアドレス（IP・プロトコル・ポートの組でユニーク） |
| `mac_address` | TEXT | MACアドレス |
| `manufacturer` | TEXT | メーカー名 |
| `model` | TEXT | 機種名 |
| `protocol` | TEXT | プロトコル |
| `port` | INTEGER | ポート番号 |
| `cpu_type` | TEXT | CPUタイプ |
| `firmware_version` | TEXT | ファームウェアバージョン |
| `first_seen` | TEXT | 初回検出日時 |
| `last_seen` | TEXT | 最終検出日時 |

#### `scan_sessions` - スキャンセッション
| カラム | 型 | 説明 |
|--------|-----|------|
| `id` | INTEGER | 主キー |
| `started_at` | TEXT | 開始日時 |
| `completed_at` | TEXT | 完了日時 |
| `mode` | TEXT | スキャンモード |
| `plc_count` | INTEGER | PLC数 |
| `success_count` | INTEGER | 成功数 |
| `error_count` | INTEGER | エラー数 |
| `status` | TEXT | ステータス |

#### `data_points` - 取得データ
| カラム | 型 | 説明 |
|--------|-----|------|
| `id` | INTEGER | 主キー |
| `session_id` | INTEGER | セッションID |
| `plc_ip` | TEXT | PLC IPアドレス |
| `protocol` | TEXT | スキャンしたプロトコル（スキーマ v3 以降） |
| `port` | INTEGER | スキャンしたポート（スキーマ v3 以降） |
| `address` | TEXT | アドレス |
| `value` | INTEGER | 値 |
| `raw_hex` | TEXT | 16進数表記 |
| `data_type` | TEXT | データ型 |
| `converted_value` | TEXT | 変換後の値 |
| `display_value` | TEXT | 表示用の値 |
| `status` | TEXT | ステータス |
| `timestamp` | TEXT | タイムスタンプ |

#### `denied_addresses` - アクセス拒否アドレス
| カラム | 型 | 説明 |
|--------|-----|------|
| `id` | INTEGER | 主キー |
| `session_id` | INTEGER | セッションID |
| `plc_ip` | TEXT | PLC IPアドレス |
| `protocol` | TEXT | スキャンしたプロトコル（スキーマ v3 以降） |
| `port` | INTEGER | スキャンしたポート（スキーマ v3 以降） |
| `address` | TEXT | アドレス |
| `status` | TEXT | ステータス |
| `timestamp` | TEXT | タイムスタンプ |

#### `data_history` - データ変更履歴
| カラム | 型 | 説明 |
|--------|-----|------|
| `id` | INTEGER | 主キー |
| `plc_ip` | TEXT | PLC IPアドレス |
| `protocol` | TEXT | スキャンしたプロトコル（スキーマ v3 以降） |
| `port` | INTEGER | スキャンしたポート（スキーマ v3 以降） |
| `address` | TEXT | アドレス |
| `old_value` | INTEGER | 旧値 |
| `new_value` | INTEGER | 新値 |
| `changed_at` | TEXT | 変更日時 |

同じIPを複数のプロトコルで読んだ場合も、`protocol`・`port` で区別されます（変更履歴はIP・プロトコル・ポート・アドレスの組で比較）。
既存のデータベースは、本ツールで開いたときに自動で v3 に移行されます。

## インデックス

パフォーマンス最適化のため、以下のインデックスが自動作成されます：

- `idx_data_points_plc_ip` - data_points.plc_ip
- `idx_data_points_plc_addr_id` - data_points(plc_ip, address, id)
- `idx_data_points_target` - data_points(plc_ip, protocol, port, address, id)
- `idx_data_points_address` - data_points.address
- `idx_data_points_timestamp` - data_points.timestamp
- `idx_data_points_session` - data_points.session_id
- `idx_denied_plc_ip` - denied_addresses.plc_ip
- `idx_plcs_ip` - plcs.ip_address
- `idx_plcs_identity` - plcs(ip_address, protocol, port)（一意）
- `idx_history_plc_ip` - data_history.plc_ip
- `idx_history_address` - data_history.address
- `idx_history_changed_at` - data_history.changed_at

## 注意事項

- スクリプト実行には `sqlite3` コマンドが必要です
- Python版は追加の依存関係なしで動作します
- バックアップはタイムスタンプ付きで自動命名されます
- `reset` コマンドは確認プロンプトが表示されます


