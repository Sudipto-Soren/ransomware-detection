<div align="center">

# 🛡️ AI-Assisted Cloud-Aware Ransomware Detection System

**Kernel-Level Detection and Recovery for Windows Environments**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-Academic-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)

*Major Project — Department of Information Science and Engineering*
*Siddaganga Institute of Technology, Tumakuru — 2025–26*

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Module Guide](#module-guide)
- [Dataset](#dataset)
- [ML Model Results](#ml-model-results)
- [API Reference](#api-reference)
- [Team](#team)

---

## Overview

Modern ransomware attacks encrypt user files and immediately synchronize them to cloud storage, corrupting legitimate backups before traditional detection systems can respond. Existing approaches rely on entropy-based or signature-based detection that triggers only after significant damage has occurred.

This project implements a **real-time, proactive ransomware detection and recovery system** that:

- Monitors file-system activity at the **Windows kernel level** via a WDK mini-filter driver
- Extracts **16 behavioral features** from observed I/O patterns
- Classifies processes using an **ensemble of ML models** (Random Forest, XGBoost, Isolation Forest)
- **Intercepts suspicious file uploads** before they reach cloud storage
- **Automatically restores clean file versions** from a copy-on-write version store

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Windows Kernel Space                    │
│   ┌─────────────────────────────────────────────────┐   │
│   │   WDK Mini-Filter Driver  (IRP_MJ_WRITE, etc.)  │   │
│   └────────────────────┬────────────────────────────┘   │
└────────────────────────│────────────────────────────────┘
                         │  FltSendMessage (event stream)
                         ▼
              ┌─────────────────────┐
              │  Monitor Service    │  ← user-mode event listener
              └──────────┬──────────┘
                         │  JSON events (docs/event-schema.json)
                         ▼
              ┌─────────────────────┐
              │ Feature Extraction  │  ← 16 behavioral features/session
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   ML Detection      │  ← RF + XGBoost + Isolation Forest
              └──────────┬──────────┘
                         │  verdict + risk score
               ┌─────────┴──────────┐
               ▼                    ▼
    ┌──────────────────┐  ┌──────────────────────┐
    │ Cloud Protection │  │   Recovery System     │
    │ (quarantine sync │  │ (copy-on-write store  │
    │  staging folder) │  │  + VSS integration)   │
    └──────────────────┘  └──────────────────────┘
               │                    │
               └─────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │   FastAPI Backend   │  ← REST API + PostgreSQL
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  React Dashboard    │  ← live monitoring UI
              └─────────────────────┘
```

---

## Key Features

| Feature | Description |
|---|---|
| **Kernel-level monitoring** | WDK mini-filter driver hooks `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` |
| **Behavioral detection** | 16 features including files/sec, overwrite ratio, extension churn, sequential access score |
| **Zero-day capability** | Isolation Forest flags novel ransomware families by anomaly, not signature |
| **Cloud protection** | Intercepts files before OneDrive / Google Drive / Dropbox sync |
| **Auto-recovery** | Copy-on-write version store restores clean files in one click |
| **Live dashboard** | React UI with 5-second polling — threats, risk scores, restore button |
| **Own dataset** | Custom-generated labeled dataset from a safe, reversible behavioral simulator |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Kernel driver | C/C++, Windows Driver Kit (WDK), Visual Studio |
| Simulator & ML | Python 3.11+, scikit-learn, XGBoost, pandas, numpy, psutil |
| Backend API | FastAPI, SQLAlchemy, SQLite (dev) / PostgreSQL (prod) |
| Dashboard | React 18, Vite |
| Deployment | Docker (PostgreSQL), uvicorn |

---

## Project Structure

```
ransomware-detection/
│
├── driver/                        # Track A — Windows only
│   └── minifilter/                # WDK mini-filter driver (C/C++)
│
├── simulator/                     # Track B
│   ├── utils/
│   │   └── event_logger.py        # shared event schema writer
│   ├── create_sandbox.py          # generates disposable test files
│   ├── benign_generator.py        # mimics normal user file activity
│   ├── ransomware_pattern_generator.py  # safe, reversible I/O simulator
│   ├── restore_sandbox.py         # undoes simulator runs (XOR is self-inverse)
│   ├── run_dataset_collection.sh  # runs 40+40 sessions automatically
│   ├── replay_to_backend.py       # sends collected events to the API
│   └── requirements-simulator.txt
│
├── feature-extraction/            # Track B
│   ├── extractor.py               # events.ndjson → labeled features.csv
│   └── output/
│       └── features.csv
│
├── ml-model/                      # Track B
│   ├── train.py                   # trains RF + XGBoost + IF, exports best
│   ├── models/
│   │   ├── best_model.joblib
│   │   ├── feature_columns.json
│   │   └── evaluation_report.json
│   └── plots/
│       ├── confusion_matrices.png
│       └── feature_importance.png
│
├── backend/                       # Track C
│   ├── main.py                    # FastAPI app — all routes
│   ├── config.py                  # env-var-driven settings
│   ├── database.py                # SQLAlchemy ORM models
│   ├── schemas.py                 # Pydantic request/response schemas
│   └── services/
│       ├── detection.py           # model loading + inference
│       ├── cloud.py               # sync-staging interception
│       └── recovery.py            # copy-on-write version store
│
├── dashboard/                     # Track D
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx                # main layout + 5s polling loop
│       ├── api.js                 # all backend calls
│       └── components/
│           ├── StatusBar.jsx
│           ├── MetricCards.jsx
│           ├── SessionFeed.jsx
│           ├── ThreatTable.jsx
│           └── CloudPanel.jsx
│
└── docs/
    ├── event-schema.json          # shared contract: driver → backend
    └── event-schema.md            # field-by-field explanation
```

---

## Getting Started

### Prerequisites

- **macOS / Linux** — Tracks B, C, D (all Python + Node work)
- **Windows 11 VM** — Track A (kernel driver only)
- Python 3.11+
- Node.js 18+
- Git

### 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ransomware-detection.git
cd ransomware-detection
```

### 2 — Python environment

```bash
cd simulator
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-simulator.txt
```

### 3 — Generate the dataset

```bash
# Create sandbox of dummy files
python create_sandbox.py --sandbox-path ./test-sandbox

# Run 40 benign + 40 ransomware-pattern sessions (~1.5 hours)
chmod +x run_dataset_collection.sh
./run_dataset_collection.sh
```

### 4 — Extract features and train

```bash
# Extract behavioral features
python ../feature-extraction/extractor.py \
    --log ./logs/events.ndjson \
    --out ../feature-extraction/output/features.csv

# Train and compare models
cd ../ml-model
pip install -r ../simulator/requirements-ml.txt
python train.py --features ../feature-extraction/output/features.csv --out-dir .
```

### 5 — Start the backend

```bash
cd ../backend
mkdir -p services && touch services/__init__.py
pip install -r ../simulator/requirements-backend.txt
uvicorn main:app --reload --port 8000
# Swagger UI: http://localhost:8000/docs
```

### 6 — Start the dashboard

```bash
cd ../dashboard
npm install
npm run dev
# Open: http://localhost:5173
```

### 7 — Replay events into the system

```bash
cd ../simulator
python replay_to_backend.py --log ./logs/events.ndjson --delay 0.3
```

Watch the dashboard populate with live sessions, threats, and quarantine events.

---

## Module Guide

### Behavioral Features Extracted

| Feature | Benign | Ransomware |
|---|---|---|
| `files_modified_per_sec` | < 0.5 | 5 – 50 |
| `overwrite_ratio` | 0.0 – 0.4 | 0.85 – 1.0 |
| `extension_change_ratio` | 0.0 | 0.9 – 1.0 |
| `sequential_score` | ≈ 0.0 | ≈ 1.0 |
| `mean_entropy_delta` | ≈ 0.0 | > 0 (real encryption) |
| `max_files_per_10sec` | 0 – 3 | 15 – 80 |
| `unique_dirs_touched` | 1 – 4 | 5 – 7 |

### Ransomware Simulator Safety

The `ransomware_pattern_generator.py` is **not ransomware**. It:
- Applies a single-byte XOR transform (`0xA5`) — a classical textbook cipher, self-inverse and publicly documented
- Operates **only** on the `test-sandbox/` folder you point it at
- Is fully reversible: `python restore_sandbox.py --sandbox ./test-sandbox`
- Contains no encryption keys, C2 communication, or payload delivery

---

## Dataset

This project uses a **custom-generated labeled dataset** rather than public malware corpora, for three reasons:

1. Public datasets contain raw binaries, not the behavioral feature logs this system needs
2. We control ground truth — every row is labeled with certainty because we generated it
3. The simulator produces varied sessions (randomized speed, file count, directory spread) to avoid the model memorizing a single pattern

**Dataset composition:**
- 40 benign sessions (human-pace file activity, 90s each)
- 40 ransomware-pattern sessions (machine-pace, varied speed 5–30 files/sec)
- 16 features per session
- Split: 80% train / 20% test, stratified

---

## ML Model Results

Three models trained and compared on the same train/test split:

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| **Random Forest** | — | — | — | — |
| **XGBoost** | — | — | — | — |
| **Isolation Forest** | — | — | — | — |

*Results populate after running `ml-model/train.py` on the collected dataset.*

**Why three models?**
- **Random Forest / XGBoost** — supervised classifiers; strong F1 on known patterns
- **Isolation Forest** — unsupervised anomaly detector; catches novel ransomware families that weren't in the training data, at the cost of a lower headline F1

---

## API Reference

Full interactive docs available at `http://localhost:8000/docs` when the backend is running.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | System health, model loaded, threat counts |
| `GET` | `/api/stats` | Summary stats for dashboard cards |
| `POST` | `/api/sessions/ingest` | Receive events, run inference, store result |
| `GET` | `/api/sessions` | List all monitored sessions |
| `GET` | `/api/threats` | List detected ransomware sessions |
| `POST` | `/api/recovery/restore/{id}` | Trigger file rollback for a session |
| `GET` | `/api/cloud/quarantine` | List files blocked from cloud sync |

---

## Team

| Name | USN | Track |
|---|---|---|
| Sachin Kumar Tiwari | 1SI23IS084 | ML & Data (Track B) |
| Shabd Swaroop | 1SI23IS092 | Backend & Recovery (Track C) |
| Sudipto Soren | 1SI23IS106 | Frontend & Integration (Track D) |
| Vishal Patil | 1SI23IS124 | Kernel Driver (Track A, Windows) |

**Guide:** Dr. Ramu S
**Batch:** B31 — Department of ISE, SIT Tumakuru
**Academic Year:** 2025–26

---

<div align="center">
<sub>Built as a major project for academic purposes. The ransomware simulator is safe, reversible, and sandbox-contained.</sub>
</div>