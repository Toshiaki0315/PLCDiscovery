# PLC Simulators

PLCが無い環境でPLC Discoveryツールをテストするためのソフトウェアシミュレーターです。

## 対応プロトコル

| シミュレーター | プロトコル | デフォルトポート | 代替ポート |
|---------------|-----------|-----------------|-----------|
| SLMP Simulator | SLMP (MC Protocol 3E) | 5001 | - |
| Modbus Simulator | Modbus/TCP | 502 | 1502 |
| EtherNet/IP Simulator | CIP over EtherNet/IP | 44818 | - |
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
python run_all.py            # 既定は 0.0.0.0（全インターフェース）で待ち受け
python run_all.py --host 127.0.0.1
```

これにより以下のシミュレーターが起動します：
- SLMP: `localhost:5001`
- Modbus/TCP: `localhost:1502`
- EtherNet/IP: `localhost:44818`
- S7: `localhost:1102`
- FINS: `localhost:9600` (UDP / TCP)

### 個別起動

```bash
# SLMP
python slmp_simulator.py --host 0.0.0.0 --port 5001

# Modbus/TCP
python modbus_simulator.py --host 0.0.0.0 --port 1502

# EtherNet/IP
python ethernet_ip_simulator.py --host 0.0.0.0 --port 44818

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
| S7 | 500-550 |
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
| `--host` | バインドするホストアドレス | 0.0.0.0 |
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
- SendRRData (Get Attribute All)

**デバイス情報：**
- Vendor ID: 0x0001 (Rockwell)
- Device Type: 0x0E (PLC)
- Product Name: "EIP Simulator PLC"

### S7 Simulator

シーメンス S7commプロトコルをシミュレート。

**対応ファンクション：**
- Setup Communication
- Read Var (DB, M領域)

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
2. バインドアドレスを確認（0.0.0.0 = 全インターフェース）
3. シミュレーターのログでエラーを確認

### Modbus/S7の特権ポート

ポート502や102を使用する場合はroot権限が必要：

```bash
sudo python modbus_simulator.py --port 502
```

または代替ポート（1502, 1102）を使用。

