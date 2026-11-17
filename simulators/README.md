# PLC Simulators

PLCが無い環境でPLC Discoveryツールをテストするためのソフトウェアシミュレーターです。

## 対応プロトコル

| シミュレーター | プロトコル | デフォルトポート | 代替ポート |
|---------------|-----------|-----------------|-----------|
| SLMP Simulator | SLMP (MC Protocol 3E) | 5001 | - |
| Modbus Simulator | Modbus/TCP | 502 | 1502 |
| EtherNet/IP Simulator | CIP over EtherNet/IP（SLC 形式：データファイル） | 44818 | - |
| EtherNet/IP Simulator（Logix 形式） | CIP over EtherNet/IP（タグ） | 44819 | - |
| EtherNet/IP Simulator（オムロン NJ/NX 形式） | CIP over EtherNet/IP（変数） | 44820 | - |
| S7 Simulator | S7comm over ISO-on-TCP | 102 | 1102 |
| FINS Simulator | FINS/UDP + FINS/TCP | 9600 | - |

> **Note**: ポート502と102は特権ポート（1024未満）のため、root権限なしで実行する場合は代替ポートを使用します。

## クイックスタート

### 起動スクリプト（おすすめ）

| OS | 起動方法 |
|----|---------|
| Windows | `start_simulators.bat` をダブルクリック |
| macOS | `start_simulators.command` をダブルクリック、または `./start_simulators.sh` |
| Linux | `./start_simulators.sh` |

- 止めるときは Ctrl+C を押します
- 待ち受けアドレスは `127.0.0.1`（このPCからのみ接続可）です。他のPCから接続する場合は `--host 0.0.0.0` を付けます
  （工場のネットワーク上では、本物のPLCと紛らわしいため使わないでください）
- 標準ライブラリだけで動くので、パッケージのインストールは不要です（`.venv` があればそれを使います）
- 起動時に、各シミュレータへ接続する `plc_scanner.py` のコマンド例を表示します
- **探索で見つけるには**、GUI の「IP範囲を指定」に `127.0.0.1` を入力します（CLI: `--mode discover --ip-range 127.0.0.1`）。
  「同じネットワーク（自動）」は LAN 上の他の機器を調べるため、このPCのシミュレータは見つかりません。
  127.0.0.1 の探索では、シミュレータ用のポート（Modbus 1502、S7 1102）も調べ、応答したプロトコルごとに1行ずつ表示します

### 全シミュレーター一括起動（直接実行）

```bash
cd simulators
python run_all.py                  # 既定は 127.0.0.1（このPCからのみ接続可）
python run_all.py --host 0.0.0.0   # 他のPCからも接続させる場合（工場LANでは注意）
```

これにより以下のシミュレーターが起動します：
- SLMP: `localhost:5001`
- Modbus/TCP: `localhost:1502`
- EtherNet/IP: `localhost:44818`（SLC 形式：N7 / B3）
- EtherNet/IP Logix: `localhost:44819`（タグ）
- EtherNet/IP オムロン NJ/NX: `localhost:44820`（変数）
- S7: `localhost:1102`
- FINS: `localhost:9600` (UDP / TCP)

### 個別起動

```bash
# SLMP
python slmp_simulator.py --host 0.0.0.0 --port 5001

# Modbus/TCP
python modbus_simulator.py --host 0.0.0.0 --port 1502

# EtherNet/IP（SLC 形式）
python ethernet_ip_simulator.py --host 0.0.0.0 --port 44818

# EtherNet/IP（Logix 形式：タグ）
python ethernet_ip_simulator.py --host 0.0.0.0 --port 44819 --mode logix

# EtherNet/IP（オムロン NJ/NX 形式：変数）
python ethernet_ip_simulator.py --host 0.0.0.0 --port 44820 --mode omron

# S7
python s7_simulator.py --host 0.0.0.0 --port 1102
```

## テスト方法

### 探索テスト

```bash
# ローカルホストのシミュレーターを検出
python plc_scanner.py --mode discover --ip-range 127.0.0.1
```

### データ読み取りテスト

```bash
# SLMPシミュレーターからDレジスタを読み取り
python plc_scanner.py --mode range --target 127.0.0.1 --protocol slmp --device D --range 0-100

# Modbusシミュレーターからホールディングレジスタを読み取り
python plc_scanner.py --mode range --target 127.0.0.1 --protocol modbus --port 1502 --device HR --range 0-100
```

### エラーハンドリングテスト

各シミュレーターにはアクセス不可アドレス範囲が設定されています：

| シミュレーター | 拒否アドレス範囲 |
|---------------|-----------------|
| SLMP | D5000-D5100, D7000-D7050 |
| Modbus | 5000-5100, 8000-8050 |
| EtherNet/IP | 100-150 |
| S7 | バイト位置 500-550（本ツールのアドレスはワード単位のため DB250-DB275） |
| FINS | DM5000-5100, HR1000-1050 |

二分探索エラー回避アルゴリズムのテスト：

```bash
# 拒否範囲を含む範囲を読み取り
python plc_scanner.py --mode range --target 127.0.0.1 --protocol slmp --device D --range 4900-5200
```

## コマンドラインオプション

### 共通オプション

| オプション | 説明 | デフォルト |
|-----------|------|-----------|
| `--host` | バインドするホストアドレス | 127.0.0.1 |
| `--port` | リッスンポート | プロトコル依存 |
| `--denied` | アクセス拒否範囲（カンマ区切り） | シミュレーター依存 |

### 例

```bash
# カスタム拒否範囲を指定
python slmp_simulator.py --denied "100-200,500-600"

# 特定インターフェースのみにバインド
python modbus_simulator.py --host 192.168.1.100 --port 502
```

## シミュレーター詳細

### SLMP Simulator

三菱電機 SLMP/MCプロトコル（3Eフレーム）をシミュレート。

**対応コマンド：**
- バッチ読み出し（ワード単位）
- バッチ読み出し（ビット単位）

**サンプルデータ：**
- D0-D999: D[n] = n * 10
- D100 = 0x1234, D101 = 0xABCD
- M0-M99: 交互に0/1

### Modbus Simulator

Modbus/TCPプロトコルをシミュレート。

**対応ファンクションコード：**
- FC01: Read Coils
- FC02: Read Discrete Inputs
- FC03: Read Holding Registers
- FC04: Read Input Registers
- FC2B/0E: Read Device Identification

**サンプルデータ：**
- HR0-HR999: HR[n] = n * 5
- HR100 = 0x1234, HR101 = 0xABCD
- IR0-IR499: IR[n] = 1000 + n

### EtherNet/IP Simulator

EtherNet/IP（CIP）プロトコルをシミュレート。

**対応コマンド：**
- Register Session
- List Identity
- List Services
- SendRRData (Get Attribute All, Forward Open / Forward Close)
- SendUnitData（PCCC の型付き読み出し：整数ファイル N7・ビットファイル B3。pycomm3 の SLCDriver で読める）

**デバイス情報：**
- Vendor ID: 0x0001 (Rockwell)
- Device Type: 0x0E (PLC)
- Product Name: "EIP Simulator PLC"（SLC 形式）／"1756-L83E/B LOGIX5583E Sim"（Logix 形式）／"NJ501-1300 Sim"（オムロン形式。Vendor ID は 47 = OMRON）

**Logix 形式（`--mode logix`、run_all では 44819 番）：**

pycomm3 の LogixDriver（ControlLogix / CompactLogix 用）で接続・読み出しできるように、次の通信に応答します。

- 識別情報（Unconnected Send 経由の Get Attributes All）、プログラム名
- タグ一覧（Get Instance Attribute List。コントローラスコープと、プログラム `MainProgram` のスコープ）
- 構造体の定義（テンプレートの属性・定義の読み出し）
- タグ読み出し（Read Tag）、複数まとめての要求（Multiple Service Packet）、大きな配列の分割読み出し（Read Tag Fragmented）。構造体全体・メンバー（`Motor.Speed`）・プログラムスコープのタグ（`Program:MainProgram.Step`）

| タグ | 型 | 値 |
|------|----|----|
| Speed | DINT | 1500 |
| Temp | REAL | 23.5 |
| Running | BOOL | 1 |
| Counter | INT | 42 |
| Recipe | DINT[10] | 0, 10, 20, ... 90 |
| Trend | INT[600] | 0〜599（1回の応答に収まらないため分割読み出しになる） |
| Motor | MotorData（構造体：Speed DINT / Current REAL / Count INT） | 1200 / 3.5 / 7 |
| Program:MainProgram.Step | DINT | 3 |
| Program:MainProgram.Setpoint | REAL | 50.0 |

```bash
python plc_scanner.py --mode range --target 127.0.0.1 --protocol eip --port 44819 --tags "Speed,Temp,Recipe[2]{3},Motor,Program:MainProgram.Step"
```

**オムロン NJ/NX 形式（`--mode omron`、run_all では 44820 番）：**

実機の NJ / NX と同じく、プログラム名やタグ一覧の要求には応答しません（pycomm3 の LogixDriver では接続できない）。本ツールは汎用の CIP 接続に切り替え、変数名を指定した読み出し（Read Tag Fragmented）で値を読みます。

| 変数 | 型 | 値 |
|------|----|----|
| Temperature | REAL | 25.5 |
| Pressure | LREAL | 0.101325 |
| TotalCount | UDINT | 123456 |
| StatusWord | WORD | 0x00FF |
| Values | INT[20] | 0, 2, 4, ... 38 |
| History | DINT[300] | 0〜299（分割読み出しになる） |
| Motor | MotorData（構造体） | 900 / 2.5 / 4 |

```bash
python plc_scanner.py --mode range --target 127.0.0.1 --protocol eip --port 44820 --tags "Temperature,Pressure,Values[0]{5},Motor.Speed"
```

構造体の変数は、メンバー（`Motor.Speed`）を指定すると読めます。全体（`Motor`）は `NG_UNSUPPORTED` になります（タグ一覧がないため構造体の並びが分からない）。書き込みには対応していません（本ツールは読み取り専用のため不要）。

### S7 Simulator

シーメンス S7commプロトコルをシミュレート。

**対応ファンクション：**
- Setup Communication
- Read Var (DB, M領域)
- CPU 情報の読み出し（USER_DATA の SZL 0x001C。snap7 の `get_cpu_info()`）：機種名 "CPU 1515-2 PN Sim"、システム名 "S7-1500 Sim"。探索結果のメーカー・機種に表示されます

**サンプルデータ：**
- DB1: 1000ワードのテストパターン
- DB2: 500バイトのシーケンシャルデータ
- M0-M99: バイトデータ

### FINS Simulator

オムロン FINS プロトコルを UDP と TCP の両方でシミュレート（同じポート、同じメモリ内容）。

```bash
python simulators/fins_simulator.py --port 9600                  # UDP + TCP（既定）
python simulators/fins_simulator.py --port 9600 --transport tcp  # TCP のみ
```

**対応コマンド：**
- Memory Area Read (0x0101)
- FINS/TCP: ノードアドレス要求（コマンド 0 → 応答 1）、FINS フレーム送信（コマンド 2）
  - クライアントノードは要求値が 0 のとき 10〜249 から自動割り当て、PLC ノードは 1
  - ノードアドレス交換前の FINS フレーム、未対応コマンド、"FINS" 以外のヘッダーには
    エラー通知（コマンド 3）を返す（ヘッダー不正時は切断）

**サンプルデータ：**
- DM0-DM99: 温度データ（200 前後のランダム値）
- DM100-DM199: DM[n] = n * 10
- DM200-DM299: ランダム値
- DM300-DM999: DM[n] = n
- HR0-HR499: HR[n] = n * 2
- W0-W199: ランダム値（0〜255）

## アーキテクチャ

```
simulators/
├── __init__.py              # パッケージ初期化
├── README.md               # このファイル
├── run_all.py              # 全シミュレーター一括起動
├── slmp_simulator.py       # SLMP シミュレーター
├── modbus_simulator.py     # Modbus/TCP シミュレーター
├── ethernet_ip_simulator.py # EtherNet/IP シミュレーター
├── s7_simulator.py         # S7 シミュレーター
└── fins_simulator.py       # FINS シミュレーター
```

## トラブルシューティング

### ポートが使用中

```bash
# 使用中のポートを確認
lsof -i :5001

# 別のポートを指定
python slmp_simulator.py --port 5002
```

### 接続できない

1. ファイアウォール設定を確認
2. バインドアドレスを確認（既定の 127.0.0.1 はこのPCからのみ。他のPCからは `--host 0.0.0.0`）
3. シミュレーターのログでエラーを確認

### Modbus/S7の特権ポート

ポート502や102を使用する場合はroot権限が必要：

```bash
sudo python modbus_simulator.py --port 502
```

または代替ポート（1502, 1102）を使用。

