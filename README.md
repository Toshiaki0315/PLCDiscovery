# PLC Discovery Tool

工場ネットワーク内のマルチベンダーPLCを自動検出し、デバイスデータを読み取り専用で収集するツールです。

## 特徴

- **マルチベンダー対応**: 三菱電機、キーエンス、オムロン、シーメンス、ロックウェル等
- **マルチプロトコル対応**: SLMP、EtherNet/IP、Modbus/TCP、S7、FINS通信
- **安全設計**: 読み取り専用、PLCを停止させない
- **エラー耐性**: 通信エラーが発生しても継続、二分探索による不正アドレス特定
- **スマートリトライ**: 指数バックオフとサーキットブレーカーによる自動リトライ
- **CSV出力**: 後でデータ解析しやすい形式で保存
- **設定ファイル対応**: YAML/JSON形式で設定をファイル管理
- **複数PLC並列処理**: 複数PLCを同時にスキャン
- **監査ログ**: 全通信を監査用に記録
- **リッチな進捗表示**: 見やすいプログレスバーとテーブル表示
- **データ型変換**: FLOAT、DWORD、STRING等のデータ型サポート
- **通知機能**: Webhook、Slack、Teams連携
- **Docker対応**: コンテナ環境での実行
- **SQLite出力**: データベースへの永続化と履歴追跡
- **レポート生成**: HTML/PDF/JSON形式のレポート出力

## 要件

- Python 3.10以上
- 対応OS: Windows, macOS, Linux

## かんたん起動（起動スクリプト）

Python 3.10 以上をインストールしてあれば、起動スクリプトをダブルクリック（または実行）するだけで使えます。
初回のみ、プロジェクト内に仮想環境（`.venv`）を作り、必要なパッケージを自動でインストールします（インターネット接続が必要です）。
2回目以降は `requirements.txt` が変わったときだけ再インストールします。

| 用途 | Windows | macOS / Linux |
|------|---------|---------------|
| GUI を起動 | `start_gui.bat` をダブルクリック | `./start_gui.sh`（macOS は `start_gui.command` をダブルクリックでも可） |
| コマンドライン版 | `plc_scanner.bat <オプション>` | `./plc_scanner.sh <オプション>` |
| PLC シミュレータ（テスト用） | `start_simulators.bat` をダブルクリック | `./start_simulators.sh`（macOS は `start_simulators.command` も可） |

```bat
plc_scanner.bat --mode range --target 192.168.1.10 --device D --range 0-99
```

- コマンドライン版を引数なしで実行（ダブルクリック）するとヘルプを表示します。誤ってネットワーク探索を始めないためです
- GUI には Tkinter が必要です。Windows の python.org 版には含まれています
- macOS / Linux の `start_gui.sh` は、Tkinter を含む Python を自動で探して使います（PATH 上の `python3` のほか、Homebrew・python.org の既定の場所も確認）。既存の `.venv` に Tkinter がなければ、その Python で作り直します。見つからない場合は対処方法を表示します（macOS: `brew install python-tk`、Ubuntu: `sudo apt install python3-tk`）
- 任意パッケージの `netifaces`（サブネットの自動判定）は、Windows + Python 3.10 以降では C++ ビルドツールがないと入りません。入らない場合もサブネットを /24 とみなして動作します
- やり直したいときは `.venv` フォルダーを削除してから再実行してください
- シミュレータは `127.0.0.1` で待ち受けます（詳細は [simulators/README.md](simulators/README.md)）。ポートは SLMP 5001 / Modbus 1502 / EtherNet/IP 44818（SLC 形式）・44819（Logix 形式：タグ）・44820（オムロン NJ/NX 形式：変数） / S7 1102 / FINS 9600 です。探索で見つけるには、IP範囲に `127.0.0.1` を指定します
- 探索結果は、同じIPアドレスでも応答したプロトコルごとに1行ずつ表示します（複数プロトコル対応のPLCも同様）

## インストール

```bash
# リポジトリのクローン
git clone <repository-url>
cd PLCDiscovery

# 依存ライブラリのインストール
pip install -r requirements.txt

# 任意: サブネットの自動判定（Windows + Python 3.10 以降は C++ ビルドツールが必要）
pip install -r requirements-optional.txt

# 開発用（テスト実行時）
pip install -r requirements-dev.txt
```

### オプショナル依存関係

一部の機能は追加ライブラリが必要です。インストールされていない場合でも、代替機能で動作します。

| ライブラリ | 機能 | 未インストール時の動作 |
|-----------|------|----------------------|
| `scapy` | ARP探索によるMAC取得 | ARP探索が無効化（IP探索は動作） |
| `netifaces` | 同一セグメント探索のサブネット自動判定 | サブネットを /24 とみなして探索 |
| `aiohttp` | 非同期HTTP通知 | urllibで同期通知に代替 |
| `weasyprint` または `pdfkit` | PDFレポート生成 | HTMLレポートのみ利用可能 |
| `rich` | リッチな進捗表示 | シンプルなテキスト表示に代替 |

```bash
# 全機能を有効にする場合
pip install scapy aiohttp weasyprint rich
```

## 使い方

### GUIで使う（おすすめ）

コマンドに慣れていない方は、画面操作で探索・データ収集ができます。追加インストールは不要です（Python標準の Tkinter を使用）。

```bash
python plc_gui.py
```

| タブ | できること |
|------|-----------|
| ① PLC探索 | 同じネットワーク、または指定IP範囲のPLCを探して一覧表示（メーカー・機種・型式・ファームウェア・読み方）。行をダブルクリックすると「データ収集」タブに接続先が入ります |
| ② データ収集 | 範囲指定（生産中でも可・周期実行対応）またはフルスキャン（工場停止時）でデータを読み取り。EtherNet/IP（Logix・オムロン NJ/NX）は「タグ」欄にタグ名を入れると、アドレスの代わりにタグを読みます。Logix は「一覧…」でコントローラのタグ一覧から選べます。NGのアドレスは赤色で表示され、「NGのみ表示」で絞り込めます |
| ③ 通信・出力設定 | パケット間隔・リトライ待機・タイムアウト、CSVの保存先と文字コード（UTF-8 / Shift-JIS）を設定。③〜⑤タブの設定を設定ファイルに保存・読み込み |
| ④ 通知 | Teams / Slack / Webhook の通知先を追加・編集・削除し、通知する出来事（スキャン完了・エラー・探索完了・定期報告）を選択。テスト送信、定期報告の間隔、同じ通知の最小間隔も設定 |
| ⑤ データベース | 収集データを SQLite にも保存。保存期間（日）、サイズの上限（MB）、整理の間隔（時間）を設定し、「今すぐ整理」も可能 |

- 結果はCLIと同じ形式のCSV（`discovery_result_*.csv`、`plc_data_*.csv`、`access_denied_log.csv`）で保存されます。画面下の「出力フォルダを開く」で保存先を開けます
- 実行中は「■ 停止」でいつでも止められます（PLCへの書き込みは一切行いません）
- フルスキャン開始時には、工場停止中かどうかの確認ダイアログが表示されます
- 画面には最大5,000行まで表示します。全件はCSVに保存されます
- ③〜⑤タブの設定は「設定を保存」で `plc_config.yaml`（変更可）に保存され、次回起動時に自動で読み込まれます。同じファイルを CLI の `-c` でも使えます。保存時、ファイル内のコメントは消えますが、ほかの項目（`targets` など）はそのまま残ります
- `plc_config.yaml` には通知先の URL（秘密情報）が入るため、`.gitignore` で Git の管理から外しています

> **Note**: macOS で標準の `/usr/bin/python3` を使うと古い Tk のため表示が崩れることがあります。Homebrew や python.org の Python 3.10 以降を使ってください。Linux で `No module named tkinter` が出る場合は `sudo apt install python3-tk` を実行してください。

### 探索モード (Discovery)

同一ネットワークセグメント内のPLCを自動検出:

```bash
python plc_scanner.py --mode discover
```

自動検出の対象:
- このPCがつながっている**すべてのネットワーク**（事務用LANと制御用LANの両方など）。インターネットに出られない独立した工場LANでも動作します
- 次は対象外です: 仮想ネットワーク（Hyper-V/WSL の vEthernet、VMware、VirtualBox、Docker、VPN など）、
  /22（1,022台）より大きいネットワーク、リンクローカル（169.254.x.x）。必要な場合は `--ip-range` で指定してください
- 1台ごとに各プロトコルを同時に問い合わせるため、応答しないアドレスは約1秒で次へ進みます（/24 で最大30秒程度）

指定IPレンジ内のPLCを検出:

```bash
python plc_scanner.py --mode discover --ip-range "192.168.1.0/24"
```

### フルスキャンモード (Full Scan)

工場停止時用。PLCの主要デバイス範囲を一括取得:

```bash
python plc_scanner.py --mode full --target 192.168.1.10
```

読み取る範囲（プロトコルごとに固定）:

| プロトコル | 範囲 |
|---|---|
| SLMP | D0-8191, M0-8191, W0-2047, R0-32767 |
| EtherNet/IP | D0-255 (N7), M0-255 (B3)。PLC-5/SLC/MicroLogix のみ（Logix 等はタグ方式のため NG_UNSUPPORTED） |
| Modbus/TCP | HR0-9999, IR0-9999 |
| S7 | DB1 のワード 0-32767 |
| FINS (UDP/TCP) | DM0-999, HR0-499, W0-199 |

プロトコルを明示的に指定:

```bash
python plc_scanner.py --mode full --target 192.168.1.10 --protocol slmp
```

### 範囲指定モード (Range Mode)

稼働時用。指定範囲のみを取得:

```bash
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-1000
```

定期実行（60秒間隔）:

```bash
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-100 --interval 60
```

アドレスは **10進数** で指定します。三菱電機の X・Y・B・W は GX Works などで16進数表示ですが、
本ツールでは `--range`・設定ファイル・CSV のいずれも10進数です（PLCへの送信時に16進数へ変換します）。

| GX Works の表記 | `--range` の指定 | CSV のアドレス |
|---|---|---|
| X0〜X1F | `--device X --range 0-31` | X0〜X31 |
| W100〜W1FF | `--device W --range 256-511` | W256〜W511 |

1つの範囲で読めるのは最大 1,048,576 点です（それを超える指定は接続前にエラー）。

### EtherNet/IP のタグ（Logix）・変数（オムロン NJ/NX）を読む

ControlLogix / CompactLogix とオムロン NJ / NX は、アドレスではなくタグ名（変数名）でデータを扱います。範囲指定モードで `--tags` を指定してください（読み取り専用）。

```bash
python plc_scanner.py --mode range --target 192.168.1.20 --protocol eip --tags "Temp,Speed,Recipe[0]{10}"
```

- 構造体（UDT）のタグは、メンバーごとの行（`Motor.Speed`、`Motor.Current` …）として出力します。メンバーだけを `--tags "Motor.Speed"` のように指定することもできます
- プログラムスコープのタグは `Program:プログラム名.タグ名` の形で指定します
- Logix のフルスキャン（`--mode full`）では、タグ一覧にあるタグ（コントローラスコープ・プログラムスコープ、基本型・構造体。配列は先頭1000要素まで）をすべて読みます
- オムロン NJ / NX はタグ一覧を取得できないため、フルスキャンではタグを読みません。Sysmac Studio で「ネットワーク公開」にした変数を `--tags` で指定してください
  - 構造体の変数は、メンバー（`変数名.メンバー名`）を指定します。設定ファイルの `scan.tag_members` にメンバー名を書いておくと、変数名だけの指定（`Motor`、配列なら `Motors[0]{3}`）をメンバーごとに展開します（書いていない構造体を全体で指定すると `NG_UNSUPPORTED`）
  - STRING 型の変数は文字列のまま出力します
  - 1 つずつの変数は最大 20 個をまとめて 1 回で要求し（Multiple Service）、通信回数を抑えます。配列（`{n}` 付き）は 1 つずつ分割読み出しします

```yaml
scan:
  tags: [Temperature, Motor, "Values[0]{10}"]
  tag_members:
    Motor: [Speed, Current, Count]   # Motor → Motor.Speed, Motor.Current, Motor.Count
```
- SLC / MicroLogix は従来どおり `--device D`（N7）・`--device M`（B3）で読みます
- シミュレーター（Logix 形式・オムロン形式）では確認済みです。実機での確認手順は [docs/real_device_checklist.md](docs/real_device_checklist.md) を参照してください

### データ型変換を指定したスキャン

FLOAT型でデータを読み取り:

```bash
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 100-199 --data-type FLOAT
```

型マッピングファイルを使用:

```bash
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-500 --type-mapping type_mapping.json
```

### 複数PLC同時スキャン

複数のPLCを並列でスキャン:

```bash
python plc_scanner.py --mode full --target 192.168.1.10,192.168.1.20,192.168.1.30 --max-concurrent 3
```

### 設定ファイルを使用

設定ファイルテンプレートを生成:

```bash
python plc_scanner.py --generate-config
```

設定ファイルを使用して実行:

```bash
python plc_scanner.py --config plc_config.yaml
```

### 監査ログを有効化

```bash
python plc_scanner.py --mode full --target 192.168.1.10 --audit-log ./audit.log
```

### レポート生成

スキャン結果をHTML/PDF/JSON形式でレポート出力:

```bash
# HTMLレポート
python plc_scanner.py --mode full --target 192.168.1.10 --report html

# JSONレポート
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 0-100 --report json

# PDFレポート（要weasyprintまたはpdfkit）
python plc_scanner.py --mode full --target 192.168.1.10 --report pdf

# レポートのカスタマイズ
python plc_scanner.py --mode full --target 192.168.1.10 \
  --report html \
  --report-output ./reports/scan_report.html \
  --report-title "生産ライン1 PLCスキャン結果" \
  --report-company "株式会社サンプル" \
  --report-theme dark
```

レポートには以下が含まれます:
- スキャン概要（成功/失敗率、所要時間）
- 検出されたPLC一覧
- 取得データの詳細（データ型変換結果含む）
- アクセス拒否アドレス一覧
- 視覚的なチャート（オプション）

### データベース出力

SQLiteデータベースにスキャン結果を保存:

```bash
# データベースを有効化
python plc_scanner.py --mode full --target 192.168.1.10 --database ./plc_data.db

# データベースを無効化（設定ファイルを上書き）
python plc_scanner.py --mode full --target 192.168.1.10 --no-database
```

## コマンドラインオプション

| オプション | 説明 | デフォルト |
|------------|------|------------|
| `--config`, `-c` | 設定ファイルパス (YAML/JSON) | - |
| `--generate-config [PATH]` | 設定ファイルテンプレートを生成（既存ファイルは上書きしません） | plc_config.yaml |
| `--mode`, `-m` | 動作モード (discover/full/range)。省略時は設定ファイルの `scan.mode`（明示されている場合のみ） | discover |
| `--target`, `-t` | 対象PLC IPアドレス（カンマ区切りで複数指定可。ホスト名も可）。不正な値は接続前にエラー | - |
| `--ip-range`, `-r` | スキャン対象IPレンジ | - |
| `--discover-protocols` | 探索で確認するプロトコル（カンマ区切り、例: `slmp,modbus`）。省略時は設定ファイルの `discovery.protocols`、なければ全プロトコル | 全プロトコル |
| `--protocol`, `-p` | プロトコル指定 (slmp/eip/modbus/s7/fins/fins-tcp)。fins は FINS/UDP、fins-tcp は FINS/TCP | 自動検出 |
| `--port` | ポート番号 | プロトコルデフォルト |
| `--device`, `-d` | デバイス種別 (D/M/W/R等) | D |
| `--range` | アドレス範囲 (例: 0-1000) | 0-999 |
| `--interval`, `-i` | 範囲指定モードの周期（秒、1以上）。省略時は設定ファイルの `scan.interval_seconds` | 0 (単発) |
| `--packet-interval` | パケット間隔(ms)。指定すると設定ファイルの値より優先 | 50 |
| `--retry-interval` | リトライ間隔(ms)。指定すると設定ファイルの値より優先 | 200 |
| `--request-timeout` | タイムアウト(ms)。指定すると設定ファイルの値より優先 | 5000 |
| `--max-concurrent` | 最大同時接続数。指定すると設定ファイルの値より優先 | 1 |
| `--output-dir`, `-o` | 出力ディレクトリ。指定すると設定ファイルの値より優先 | ./plc_scan_results |
| `--encoding` | CSV の文字コード（指定すると設定ファイルの値より優先）。`utf-8-sig`（BOM 付き UTF-8、Excel でそのまま開ける）／`utf-8`（BOM なし）／`shift-jis`（CP932。表せない文字は `?` に置き換え） | utf-8-sig |
| `--audit-log` | 監査ログファイルパス | - |
| `--database` | SQLiteデータベースパス | - |
| `--no-database` | データベース出力を無効化 | - |
| `--db-track-history` | データベースの変更履歴追跡を有効化 | - |
| `--report` | レポート形式 (html/pdf/json) | - |
| `--report-output` | レポート出力パス（指定したパスをそのまま使用） | 出力ディレクトリ内に自動生成 |
| `--report-title` | レポートタイトル | "PLC Discovery レポート" |
| `--report-company` | レポート記載会社名 | - |
| `--report-theme` | レポートテーマ (default/dark/light) | default |
| `--verbose`, `-v` | 詳細出力 | - |
| `--quiet`, `-q` | 進捗出力抑制 | - |
| `--no-rich` | リッチな出力を無効化 | - |
| `--data-type` | データ型変換 (FLOAT, DWORD等)。型マッピング使用時はマッピング外のアドレスに適用 | - |
| `--byte-order` | 複数ワード値の並び。little=CDAB（下位ワード先頭）、big=ABCD、little_swap=DCBA、big_swap=BADC（ワード内バイト入替）。指定すると設定ファイルの値より優先（`byte_order` を書いていない型マッピングにも適用） | little |
| `--type-mapping` | 型マッピングファイルパス | - |
| `--tags` | EtherNet/IP（Logix・オムロン NJ/NX）で読むタグ（カンマ区切り。`配列[0]{10}` で10要素）。設定ファイルでは `scan.tags` | - |
| `--hex-addresses` | 三菱（SLMP）の X/Y/B/W を16進数表記でも出力（CSV に `address_hex` 列。例: X31 → X1F）。設定ファイルでは `output.hex_addresses` | オフ |
| `--periodic-csv` | 周期実行の CSV：`per_cycle`（周期ごとに1ファイル）／`daily`（1日1ファイルに追記）。設定ファイルでは `output.periodic_csv` | per_cycle |

## 設定ファイル

`plc_config.example.yaml` を参考に設定ファイルを作成できます：

```yaml
version: "1.0"

network:
  discovery_timeout_ms: 1000
  max_concurrent: 3
  packet_interval_ms: 50

targets:
  - ip: "192.168.1.10"
    protocol: slmp
    port: 5001
    name: "Main PLC"

scan:
  mode: range        # full（全デバイス読み取り）は工場停止時のみ
  device_ranges:
    - device: D
      start: 0
      end: 8191

output:
  directory: "./plc_scan_results"
  encoding: utf-8-sig

logging:
  level: INFO
  audit_log: "./audit.log"
```

## 出力ファイル

| ファイル名 | 内容 |
|------------|------|
| `discovery_result_YYYYMMDD_HHMMSS.csv` | 検出されたPLC一覧（メーカー・機種・型式・ファームウェア・読み方〔`read_method`：アドレス／タグ一覧あり／変数名指定／データファイル〕など。識別情報が取れない機器は、プロトコルから分かるメーカー〔SLMP・S7・FINS〕と「〜対応PLC」を記入） |
| `plc_data_<IP>_YYYYMMDD_HHMMSS.csv` | PLCデバイスデータ。同じIPを複数のプロトコルで読んだ場合は `plc_data_<IP>_<プロトコル>_<ポート>_…csv` |
| `access_denied_log.csv` | アクセス不可アドレス一覧（同じIPを複数のプロトコルで読んだ場合、`plc_ip` 列は `IP (プロトコル:ポート)`） |
| `scan_summary_YYYYMMDD_HHMMSS.csv` | スキャン統計サマリー |
| `audit.log` | 監査ログ（JSON Lines形式） |

## 対応プロトコルとメーカー

| プロトコル | 対応メーカー | デフォルトポート | 備考 |
|------------|--------------|------------------|------|
| SLMP (3Eフレーム) | 三菱電機、キーエンス、パナソニック、東芝、日立産機 | 5001 | |
| EtherNet/IP | オムロン、ロックウェル、キーエンス、安川電機 | 44818 | |
| Modbus/TCP | 横河電機、富士電機、IDEC、デルタ電子 | 502 | |
| S7通信 | シーメンス | 102 | |
| FINS通信 | オムロン、キーエンス | 9600 | UDP（`fins`）と TCP（`fins-tcp`）に対応 |

## 安全上の注意

- **本ツールは読み取り専用です**。PLCへの書き込み機能は一切ありません。
- ネットワーク負荷軽減のため、適切な`--packet-interval`を設定してください。
- 工場稼働中は`--mode range`で必要な範囲のみを取得することを推奨します。
- フルスキャンは工場停止時に実施してください。

## プロジェクト構造

```
PLCDiscovery/
├── plc_scanner.py              # メインCLI
├── plc_gui.py                  # GUI（Tkinter）
├── plc_config.example.yaml     # 設定ファイルサンプル
├── requirements.txt            # 依存ライブラリ
├── requirements-dev.txt        # 開発用依存ライブラリ
├── README.md                   # このファイル
├── plc_discovery/
│   ├── __init__.py
│   ├── config.py               # 設定・定数
│   ├── config_loader.py        # 設定ファイルローダー
│   ├── data_types.py           # データ型変換モジュール
│   ├── database.py             # SQLiteデータベースモジュール
│   ├── utils.py                # ユーティリティ
│   ├── discovery.py            # 探索モジュール
│   ├── broadcast_discovery.py  # UDPブロードキャスト探索
│   ├── collector.py            # データ収集モジュール
│   ├── parallel.py             # 並列処理モジュール
│   ├── output.py               # CSV出力モジュール
│   ├── audit_log.py            # 監査ログモジュール
│   ├── progress.py             # 進捗表示モジュール
│   ├── notifications.py        # 通知機能モジュール
│   ├── report.py               # レポート生成モジュール
│   ├── retry.py                # リトライ/サーキットブレーカーモジュール
│   └── protocols/
│       ├── __init__.py
│       ├── base.py             # 基底ハンドラー
│       ├── slmp.py             # SLMP プロトコル
│       ├── ethernet_ip.py      # EtherNet/IP プロトコル
│       ├── modbus.py           # Modbus/TCP プロトコル
│       └── s7.py               # S7 プロトコル
├── tests/                      # ユニットテスト
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_config_loader.py
│   ├── test_data_types.py
│   ├── test_database.py        # データベーステスト
│   ├── test_utils.py
│   ├── test_discovery.py
│   ├── test_broadcast_discovery.py
│   ├── test_collector.py
│   ├── test_parallel.py
│   ├── test_output.py
│   ├── test_progress.py
│   ├── test_audit_log.py
│   ├── test_notifications.py   # 通知機能テスト
│   ├── test_report.py          # レポートテスト
│   ├── test_retry.py           # リトライテスト
│   ├── test_protocols.py
│   └── integration/            # 統合テスト
│       ├── conftest.py
│       ├── test_slmp_integration.py
│       ├── test_modbus_integration.py
│       └── test_binary_search.py
└── simulators/                 # テスト用ダミーPLCシミュレータ
    ├── README.md
    ├── run_all.py
    ├── slmp_simulator.py
    ├── modbus_simulator.py
    ├── ethernet_ip_simulator.py
    ├── s7_simulator.py
    └── fins_simulator.py       # FINS シミュレータ
```

## テスト

ユニットテストの実行:

```bash
# 最初に一度だけ: テスト用ライブラリ（pytest など）をインストール
pip install -r requirements-dev.txt

# 全テスト実行
pytest

# ユニットテストのみ（統合テスト除外）
pytest -m "not integration"

# カバレッジレポート付き
pytest --cov=plc_discovery --cov-report=html
```

### 統合テスト

統合テストは、テスト用のシミュレータを自動で起動・停止します。事前にシミュレータを起動する必要はありません。

```bash
pytest -m integration
```

- 通常のポート（5001、44818 など）が空いていればそれを使い、`simulators/run_all.py` などが使用中なら空いている別のポートで起動します。run_all を起動したままでもテストできます
- CI/CDパイプラインでも同じ仕組みで実行しています

## シミュレータを使用したテスト

実機PLCがない環境でのテスト:

```bash
# シミュレータを起動
python simulators/run_all.py &

# テスト実行
python plc_scanner.py --mode discover
python plc_scanner.py --mode full --target 127.0.0.1 --protocol slmp
```

## Docker

Dockerを使用した実行:

```bash
# イメージのビルド
docker build -t plc-scanner .

# ヘルプ表示
docker run --rm plc-scanner --help

# 探索モード
docker run --rm -v $(pwd)/plc_scan_results:/app/output plc-scanner \
  --mode discover --ip-range "192.168.1.0/24"
```

Docker Composeを使用した環境構築:

```bash
# シミュレータとスキャナーを起動
docker-compose up -d

# スキャナーを実行（シミュレータは一部が標準と異なるポート: Modbus 1502, S7 1102）
docker-compose run scanner --mode full --target simulators
docker-compose run scanner --mode range --target simulators --protocol modbus --port 1502 --device HR --range 0-99

# 実際の工場 LAN を探索する場合はブロードキャスト/ARP が必要なため、
# docker-compose.yml の scanner に network_mode: host を設定（Linux のみ）

# 統合テスト
docker-compose run integration-test

# 停止
docker-compose down
```

## データベース出力

SQLiteデータベースへの保存（オプション）:

### CLIでの有効化

```bash
# データベース出力を有効にしてスキャン
python plc_scanner.py --mode full --target 192.168.1.10 --database ./plc_data.db

# 変更履歴追跡を有効に
python plc_scanner.py --mode range --target 192.168.1.10 \
  --device D --range 0-100 \
  --database ./plc_data.db --db-track-history

# データベース出力を無効に（設定ファイルの設定を上書き）
python plc_scanner.py --config plc_config.yaml --no-database
```

### 設定ファイルでの有効化

```yaml
# plc_config.yaml
output:
  database:
    enabled: true
    path: "./plc_data.db"
    track_history: true
    max_history_days: 30   # これより古いデータは自動で削除（0 = 削除しない）
```

`max_history_days` より古いデータは、データベースを開いたときと、周期実行中は `cleanup_interval_hours`（既定 24 時間）ごとに、自動で削除されます。`max_size_mb` を指定すると、データ量がその値を超えないよう古いデータから削除します（0 = 上限なし）。どちらの場合も、各アドレスの最新値は残ります。

```yaml
output:
  database:
    max_history_days: 30        # 保存する期間（日、0 = 期間で削除しない）
    max_size_mb: 500            # データ量の上限（MB、0 = 上限なし）
    cleanup_interval_hours: 24  # 周期実行中に整理する間隔（時間）
```

### Pythonコードでの利用

```python
from plc_discovery import DatabaseExporter, DatabaseConfig, create_database

# シンプルな作成
db = create_database("./plc_data.db")

# 設定を指定して作成
config = DatabaseConfig(
    enabled=True,
    path="./plc_data.db",
    track_history=True,
    max_history_days=30
)
db = DatabaseExporter(config)

# セッション管理
with db.session(mode="full") as session_id:
    db.export_plc_data(data_points, "192.168.1.10", session_id)

# データ取得
plcs = db.get_plcs()
data = db.get_latest_data("192.168.1.10")
history = db.get_address_history("192.168.1.10", "D100", days=7)
changes = db.get_changes(plc_ip="192.168.1.10", days=7)
stats = db.get_statistics()

db.close()
```

### データベーステーブル

| テーブル | 説明 |
|----------|------|
| `plcs` | 発見されたPLC一覧 |
| `scan_sessions` | スキャンセッション履歴 |
| `data_points` | デバイスデータポイント |
| `denied_addresses` | アクセス拒否アドレスログ |
| `data_history` | 値変更履歴 |

## 通知機能

スキャン完了やエラー発生時に通知を送信します（GUI では「④ 通知」タブで設定できます）。

### 通知のタイミング

```yaml
notification_settings:
  report_interval_minutes: 30   # 周期実行中、各PLCの OK/NG 件数を30分ごとに送る（0 = 送らない）
  min_interval_minutes: 10      # 同じ種類の通知は10分に1回まで（0 = 制限なし）
```

通知する出来事（`events`）: `scan_complete`（スキャン完了）、`scan_error`（エラー）、`discovery_complete`（探索完了）、`status_report`（周期実行中の定期報告）、`plc_unreachable`（周期実行中の通信断・復旧）、`threshold_exceeded`（周期実行中のしきい値超過）。省略するとすべて通知します。

周期実行中に PLC が応答しなくなると、通信が途切れるたびに 1 回 `plc_unreachable` を送り、応答に戻ると止まっていた時間を付けて `plc_recovered` を送ります（CLI・GUI 共通）。どちらも `scan_error` を選んだ通知先にも届きます。

`min_interval_minutes` の制限は、通信断・復旧とその PLC ごとに、しきい値超過は PLC と条件の組ごとに数えます。ある PLC の通知が、別の PLC や別の条件の通知を止めることはありません。

### 設定ファイルでの通知設定

```yaml
# plc_config.yaml
notifications:
  # Webhook通知
  - name: main_webhook
    type: webhook
    url: "https://your-server.com/api/notifications"
    events:
      - scan_complete
      - scan_error
    
  # Slack通知
  - name: slack_alerts
    type: slack
    url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    events:
      - scan_error
      - discovery_complete
  
  # Microsoft Teams通知（Teams のワークフロー「Webhook 要求を受信したらチャネルに投稿する」の URL）
  - name: teams_alerts
    type: teams
    url: "https://YOUR-WORKFLOW-WEBHOOK-URL"
```

Teams の従来の Incoming Webhook（`outlook.office.com/webhook/...`）は廃止が進んでいます。新しく設定する場合は、Teams のワークフローで発行した Webhook の URL を指定してください。Teams には Adaptive Card 形式で送ります（従来の URL を使う場合は `format: messagecard`）。

### しきい値の監視

周期実行中、指定したアドレス（またはタグ）の値が条件を満たしたときに `threshold_exceeded` を通知します。通知は条件を満たした時点で 1 回だけ送り、値が範囲内に戻ってから再び超えたときにもう一度送ります（毎周期は送りません）。比較する値は、データ型変換をしている場合は変換後の値、そうでなければ読み取った値そのものです。読めなかったアドレスは比較しません。読み取り範囲（またはタグ）に含まれないアドレスを指定すると、最初の周期で警告を表示します（CLI はコンソール、GUI はログ欄）。

```bash
python plc_scanner.py --mode range --target 192.168.1.10 --device D --range 100-200 \
  --interval 60 --threshold "D100>80" --threshold "D150<=10"
```

```yaml
thresholds:
  - address: D100
    op: ">"          # >, >=, <, <=, ==, !=
    value: 80
    name: 炉温度      # 通知に表示する名前（任意）
```

GUI では、「周期実行」の横の「しきい値」欄に `D100>80, D200<=10` のようにカンマ区切りで入力します。

### Pythonコードでの通知

```python
from plc_discovery import (
    NotificationManager, NotificationType, NotificationPriority
)

# 通知マネージャーの初期化
manager = NotificationManager()
manager.add_slack("alerts", "https://hooks.slack.com/...")
manager.add_webhook("logging", "https://example.com/webhook")

# 通知送信
await manager.notify_scan_complete(
    plc_count=10,
    success_count=9,
    error_count=1,
    duration_seconds=45.5
)

# エラー通知
await manager.notify_error(
    error_message="Connection timeout",
    plc_ip="192.168.1.50"
)
```

詳しくは `simulators/README.md` を参照してください。

## データ型変換

PLCから読み取ったデータを様々な型に変換できます：

| データ型 | 説明 | ワード数 |
|----------|------|----------|
| WORD | 16ビット符号なし整数 | 1 |
| INT16 | 16ビット符号付き整数 | 1 |
| DWORD | 32ビット符号なし整数 | 2 |
| INT32 | 32ビット符号付き整数 | 2 |
| FLOAT | 32ビットIEEE 754浮動小数点 | 2 |
| DOUBLE | 64ビットIEEE 754倍精度浮動小数点 | 4 |
| BCD16 | 16ビットBCD（4桁） | 1 |
| BCD32 | 32ビットBCD（8桁） | 2 |
| STRING | ASCII文字列 | 可変 |
| BIT/BOOL | ビット値 | 1 |

### 使用例（設定ファイル）

```yaml
data_types:
  default_type: WORD
  default_byte_order: little
  mappings:
    - device: D          # 省略時はワードデバイスのみに適用（M/X/Y/B/SM には適用しない）
      start: 100
      end: 199
      type: FLOAT
      description: "温度データ"
    - device: D
      start: 200
      end: 299
      type: DWORD
      description: "生産カウンター"
```

複数ワードの型（FLOAT、DWORD など）は `start` を起点に組を作ります（FLOAT が 100 からなら 100-101, 102-103, …）。
STRING / RAW は `length`（1つの値のワード数）ごとに1つの値になります。省略時はマッピング範囲全体で1つの値です
（`--data-type STRING` の場合は読み取り範囲全体）。例: `start: 1000, end: 1099, type: STRING, length: 10` で20文字の文字列が10個。
途中のワードが読めなかった場合も、後続の組はずれません。値を構成する2ワード目以降の行も、元の値と16進表記のまま出力されます。

### プログラムからの使用

```python
from plc_discovery.data_types import DataTypeConverter, DataType, ByteOrder

# 2ワードからFLOATに変換
words = [0x0000, 0x3F80]  # IEEE 754 for 1.0
value = DataTypeConverter.convert(words, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
print(value)  # 1.0

# バッチ変換
words = [100, 200, 300, 400]
values = DataTypeConverter.convert_batch(words, DataType.INT16)
print(values)  # [100, 200, 300, 400]
```

## 二分探索エラー回避アルゴリズム

本ツールの重要な特徴は、アクセス不可アドレスを自動特定する二分探索アルゴリズムです：

1. 指定範囲を一括で読み出し試行
2. エラー発生時、範囲を半分に分割して再試行
3. さらにエラーが出る場合は再分割（最大12段階）
4. 1点単位まで分割してアクセス可否を判定
5. 判定されたアクセス不可アドレスは以降スキップ

範囲全体が読めない場合（ファイルレジスタ未設定、デバイスの上限を超えた範囲など）は、分割する前に
範囲の先頭と末尾を1点ずつ読み、両方とも `NG_ILLEGAL_ADDR` なら範囲全体を `NG_ILLEGAL_ADDR` とします。
1点単位まで分割すると約2N回の要求（R0-32767 で約65,000回・数時間）になるためです。
両端が読めない範囲の内側に、読めるアドレスが孤立して存在する場合は、それも NG と記録されます。

これにより、一部のアドレスがアクセス不可でも全体のスキャンが中断することなく継続されます。

## データベース管理スクリプト

SQLiteデータベースのセットアップ・管理用スクリプトが `scripts/` ディレクトリに用意されています。

### セットアップスクリプト

```bash
# シェルスクリプト版
./scripts/setup_database.sh [database_path]

# Python版
python scripts/setup_database.py [database_path]

# オプション
python scripts/setup_database.py --force ./plc_data.db  # 強制再作成
python scripts/setup_database.py --status ./plc_data.db # ステータス表示
```

### 管理スクリプト

```bash
./scripts/manage_database.sh <command> [database_path]
```

| コマンド | 説明 |
|----------|------|
| `status` | データベースのステータスと統計情報を表示 |
| `tables` | テーブル一覧と行数を表示 |
| `backup` | バックアップを作成 |
| `cleanup [日数]` | 古いデータを削除（デフォルト: 30日以前） |
| `vacuum` | データベースを最適化（容量削減） |
| `export` | CSVファイルにエクスポート |
| `reset` | すべてのデータを削除 |
| `shell` | SQLite対話型シェルを開く |

### 使用例

```bash
# データベース作成
./scripts/setup_database.sh ./plc_data.db

# ステータス確認
./scripts/manage_database.sh status ./plc_data.db

# 7日以前のデータを削除
./scripts/manage_database.sh cleanup ./plc_data.db 7

# バックアップ作成
./scripts/manage_database.sh backup ./plc_data.db

# CSVエクスポート
./scripts/manage_database.sh export ./plc_data.db
```

## 監査ログ形式

監査ログはJSON Lines形式で記録されます：

```json
{"timestamp": "2024-01-01T00:00:00", "event_type": "SESSION_START", "session_id": "xxx"}
{"timestamp": "2024-01-01T00:00:01", "event_type": "CONNECT", "plc_ip": "192.168.1.10", "status": "SUCCESS"}
{"timestamp": "2024-01-01T00:00:02", "event_type": "READ_SUCCESS", "plc_ip": "192.168.1.10", "device": "D", "address_start": 0, "address_end": 100}
```

## ライセンス

MIT License
