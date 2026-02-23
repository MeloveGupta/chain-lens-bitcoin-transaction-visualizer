# 🧩 Chain Lens  
### Bitcoin Transaction & Block Visualizer

Chain Lens is a Bitcoin transaction and block analyzer that converts raw blockchain data into structured, machine-checkable JSON and an interactive visual explanation.

It parses raw Bitcoin transactions and block files (including undo data), performs full accounting and classification, and presents the results through both a CLI and a human-friendly web visualizer.

---

## 🚀 Features

### 🔍 CLI Analyzer

- Parses raw Bitcoin transactions (hex format)
- Computes:
  - `txid` / `wtxid`
  - Fees and fee rate (sat/vB)
  - Weight & virtual bytes (BIP141)
  - SegWit savings
  - RBF signaling (BIP125)
  - Absolute & relative timelocks (BIP68)
- Script classification:
  - P2PKH
  - P2SH
  - P2WPKH
  - P2WSH
  - P2TR (Taproot)
  - OP_RETURN
- Full script disassembly (including PUSHDATA handling)
- Structured error handling
- Block parsing mode:
  - Parses `blk*.dat`
  - Parses `rev*.dat` undo data
  - XOR decoding support
  - Merkle root validation
  - BIP34 block height decoding
  - Fee aggregation & script statistics

---

### 🌐 Web Visualizer

- Single-page transaction visualizer
- Story-based explanation:
  - What happened?
  - Who paid whom?
  - What did it cost?
  - Is anything risky?
- Visual value flow diagram (inputs → outputs)
- SegWit discount comparison
- Script type badges (P2WPKH, Taproot, OP_RETURN, etc.)
- RBF and timelock explanations
- Expandable block overview with transaction list
- Technical details toggle (raw hex hidden by default)
- Works offline (no external APIs)

---

## 🏗 Architecture Overview
CLI → Transaction Parser → Script Classification → Accounting Engine
     → JSON Report

Web Server → API (/api/analyze, /api/analyze_block)
           → Frontend SPA (Story + Visual Flow + Metrics)


The CLI and Web UI share the same underlying transaction parsing logic to ensure consistency.

---

## 🛠 Installation

### Requirements

- Node.js (if using Node backend) OR Python (if using Python backend)
- Git

Clone the repository:

```bash
git clone https://github.com/yourusername/chain-lens-bitcoin-visualizer.git
cd chain-lens-bitcoin-visualizer
```
### Install dependencies:
#### If Node-based
```bash
npm install
```

#### OR if Python-based
```bash
pip install -r requirements.txt
```

### 🖥 CLI Usage
Transaction Mode
./cli.sh fixtures/transactions/example.json

Output:

Writes out/<txid>.json

Prints JSON to stdout

Block Mode
./cli.sh --block blk00000.dat rev00000.dat xor.dat

Output:

Writes out/<block_hash>.json

Does NOT print JSON to stdout

### 🌐 Web Usage

Start the web server:

```bash
./web.sh
```

You will see:

http://127.0.0.1:3000

Open the URL in your browser.

API Endpoints

GET /api/health → { "ok": true }

POST /api/analyze

POST /api/analyze_block

### 📊 Example Capabilities

Taproot keypath & scriptpath detection

Nested SegWit (P2SH-P2WPKH / P2SH-P2WSH)

Complex P2WSH witness script decoding

OP_RETURN multi-push decoding

Omni protocol detection

Non-UTF8 payload handling

Undo compression handling (P2PKH, P2SH, compressed P2PK)

### 🎬 Demo

Demo video walkthrough:

👉 https://drive.google.com/file/d/1mvjtSYbKSlzMKSe6EcqlDqLZV1EmFTEP/view?usp=sharing

### 🧠 What This Project Demonstrates

Low-level binary parsing

Bitcoin transaction serialization knowledge

Script interpretation & classification

Merkle tree computation

Undo data decoding

Systems-level debugging

CLI + Web full-stack integration

Human-centered technical explanation

### 📚 References

BIP141 (SegWit)

BIP34 (Block height in coinbase)

BIP68 (Relative timelock)

BIP125 (RBF)

BIP173 / BIP350 (Bech32 / Bech32m)

### 👨‍💻 Author

Melove
