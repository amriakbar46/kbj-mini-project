# Network Traffic Analysis Mini Project — KBJ ITS

Cybersecurity mini project untuk mata kuliah **Komputasi Berbasis Jaringan (KBJ)** di
Program Studi Magister Teknik Informatika, Institut Teknologi Sepuluh Nopember (ITS).

## ⚠️ Disclaimer

This repository contains **real malware samples** (`c2.exe`, `config.cfg`) and forensic
analysis from a controlled lab environment for **cybersecurity education purposes only**.

**DO NOT execute any binary in**
`network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/AppData-Roaming-*`
— they are real malware samples. Use only in isolated VM/sandbox.

Detection rules (YARA, Suricata, Sigma) in this repo are for **defensive purposes only**.

## 📋 Project Overview

| Case | Date | Type | Family | Confidence |
|------|------|------|--------|------------|
| Case 1 | 2024-09-04 | HTTP beacon C2 | Koi-like (hypothesis) | Medium-High |
| Case 2 | 2024-11-26 | NetSupport RAT abuse | NetSupport Manager | High |
| **Case 3** | **2025-06-13** | **BYOI PHP-based RAT** | **Agent_AGen.HR / Doina / Zusy** (VT 44/74) | **High (verified)** |

**Case 3 (v2.3)** is the deep re-analysis: compromised legitimate site → JS inject →
PowerShell stager → BYOI PHP interpreter → multi-tier C2 beaconing → 7-command RAT.

## 📁 Repository Structure

```
network-analysis/
├── pcap/                          # Raw PCAP files (3 cases) + split files
│   ├── 2024-09-04-...pcap         # Case 1 PCAP
│   ├── 2024-11-26-...pcap         # Case 2 PCAP
│   ├── 2025-06-13-...pcap         # Case 3 PCAP
│   ├── 2025-06-13-...forensic-analysis/  # Forensic bundle (c2.exe, config.cfg, php.exe, .lnk, Edge cache)
│   └── case*-split_*.pcap         # Split PCAP files (split for performance)
├── output/                        # Analysis results (CSV, JSON, PNG)
│   ├── case1/                     # Case 1 results
│   ├── case2/                     # Case 2 results
│   ├── case3/                     # Case 3 results
│   ├── cross_case_overlap_stats.csv
│   ├── master_ioc.csv             # All IOC across 3 cases
│   └── mitre_attack_navigator.json
├── reports/                       # HTML reports per case
│   ├── case1/final-network-analysis-report-pekan1-revisi.html
│   └── case1/final_case1_report_complete_embedded.html
├── scripts/                       # Python analysis tools
│   ├── analyze_tls_ja3.py         # TLS/JA3 fingerprint extraction
│   ├── beacon_analysis.py         # Beacon interval analysis
│   ├── beacon_visualization.py    # Beacon timeline + histogram
│   ├── build_*.py                 # CSV/JSON summary builders
│   ├── compute_response_variables.py
│   ├── http_payload_extractor.py  # HTTP file_data extraction
│   ├── ioc_extractor.py           # IOC extraction
│   ├── visualize_*.py             # Geo map, DNS timeline, etc.
│   ├── zeek_like_logs.py           # Zeek-style log generation
│   └── case3/                     # Case 3 v2.3 deep analysis scripts
│       ├── case3_pe_analyzer.py
│       ├── case3_config_decoder.py
│       ├── case3_payload_analyzer.py
│       ├── case3_yara_validator.py
│       ├── case3_vt_lookup.py      # VirusTotal API lookup
│       └── README.md              # Script documentation
├── docker/                        # Docker setup
│   ├── Dockerfile
│   └── requirements.txt
├── others/                        # Documentation
└── README.md                      # This file
```

## 🛠️ Tools & Setup

### Prerequisites

```bash
pip install pyshark pefile yara-python vt-py
```

### Case 3 v2.3 scripts (need VirusTotal API key)

1. Sign up free at https://www.virustotal.com
2. Get API key at https://www.virustotal.com/gui/user/USERNAME/apikey
3. Copy `network-analysis/.env.template` to `network-analysis/.env`
4. Edit `.env` and set `VT_API_KEY="your_key_here"`

### Run Case 3 v2.3 analysis

```bash
cd network-analysis
python scripts/case3/case3_pe_analyzer.py pcap/2025-06-13-.../AppData-Roaming-afUGkp/c2.exe
python scripts/case3/case3_config_decoder.py pcap/2025-06-13-.../AppData-Roaming-php/config.cfg
python scripts/case3/case3_payload_analyzer.py output/case3/payloads/http_file_data/frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin
python scripts/case3/case3_yara_validator.py scripts/case3/../case3_yara_rules.yar pcap/2025-06-13-...-forensic-analysis/ .
python scripts/case3/case3_vt_lookup.py
```

## 🔍 Case 3 v2.3 — Key Findings

**Attack chain (6 phases):**

1. **Initial Access (T1189)**: Compromised legitimate site `truglomedspa.com` (med spa
   Naples, FL) → JS inject PowerShell stager
2. **Initial Stager (T1059.001)**: Download from `dng-microsoftds.com/Gsdg4976.txt` via
   `Net.WebClient.DownloadString` + `iex`
3. **BYOI Staging (T1127)**: Download PHP 8 interpreter (~33 MB) from `windows.php.net`
4. **Persistence (T1547.001/009)**: `c2.exe` (17.5 KB) + Startup `.lnk` + HKCU Run key
5. **C2 Beaconing (T1071.001)**: 62 POST multi-tier (30/60/90/120s) to 3 Cloudflare-fronted
   domains + Cloudflare Tunnel
6. **Command Set**: 7 commands (EXE/DLL/JS/CMD/ACTIVE/AUTORUN/OFF) ready to execute

**Family (VirusTotal verified 44/74 detections):**

- ESET-NOD32: `Win64/TrojanDownloader.Agent_AGen.HR`
- Fortinet: `W64/Agent_AGen.HR!tr.dlr`
- Microsoft: `Trojan:Win64/Zusy.AHE!MTB`
- BitDefender: `Gen:Variant.Doina.100728`

**Detection rules included:**

- 4 YARA rules (`case3_yara_rules.yar`)
- 18 Suricata rules (`case3_suricata.rules`)
- 7 Sigma rules (`case3_sigma_rules.yml`)

## 👥 Authors

- 6025252002 — Kafiyatul Fithri
- 6025252005 — Dhayu Intan Nareswari
- 6025252014 — Ridho Liwardana
- 6025252010 — Yoan Amri Akbar

**Dosen Pengampu:** Hudan Studiawan, S.Kom., M.Kom., Ph.D.

## 📚 Data Source

PCAP files from [malware-traffic-analysis.net](https://malware-traffic-analysis.net) —
publicly available network traffic captures for cybersecurity training.
