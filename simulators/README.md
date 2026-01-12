# PLC Simulators

PLCが無い環境でPLC Discoveryツールをテストするためのソフトウェアシミュレーターです。

## 対応プロトコル

| シミュレーター | プロトコル | デフォルトポート | 代替ポート |
|---------------|-----------|-----------------|-----------|
| SLMP Simulator | SLMP (MC Protocol 3E) | 5001 | - |
| Modbus Simulator | Modbus/TCP | 502 | 1502 |
| EtherNet/IP Simulator | CIP over EtherNet/IP | 44818 | - |
| S7 Simulator | S7comm over ISO-on-TCP | 102 | 1102 |
| FINS Simulator | FINS/UDP | 9600 | - |

> **Note**: ポート502と102は特権ポート（1024未満）のため、root権限なしで実行する場合は代替ポートを使用します。

## クイックスタート

### 全シミュレーター一括起動

```bash
cd simulators
python run_all.py
```

これにより以下のシミュレーターが起動します：
- SLMP: `localhost:5001`
- Modbus/TCP: `localhost:1502`
- EtherNet/IP: `localhost:44818`
- S7: `localhost:1102`
- FINS: `localhost:9600` (UDP)

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

オムロン FINS/UDPプロトコルをシミュレート。

**対応コマンド：**
- Memory Area Read (0x0101)

**サンプルデータ：**
- DM0-DM999: DM[n] = n * 3
- HR0-HR499: HR[n] = 500 + n
- W0-W99: W[n] = n * 7

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

