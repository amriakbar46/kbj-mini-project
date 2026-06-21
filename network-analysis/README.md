# Network Traffic Analysis & DFIR Mini Project

## Overview

Project ini merupakan mini project analisis network traffic dan DFIR (Digital Forensics & Incident Response) menggunakan dataset PCAP.

Fokus utama project:
- Network traffic analysis
- Malware beaconing detection
- HTTP command-and-control (C2) analysis
- IOC extraction
- Threat intelligence enrichment
- Visualization & reporting
- Custom DFIR tooling menggunakan Python

---

# Objectives

Tujuan project:

1. Melakukan initial triage terhadap file PCAP
2. Mengidentifikasi suspicious network activity
3. Mengekstrak IOC (Indicator of Compromise)
4. Melakukan analisis beaconing dan C2 communication
5. Mengekstrak serta menganalisis payload HTTP
6. Mengkorelasikan hasil dengan threat intelligence
7. Membuat visualisasi traffic dan communication graph
8. Mendokumentasikan workflow DFIR secara reproducible

---

# Dataset

Dataset utama:

| Case | File | Status |
|---|---|---|
| Case 1 | `2024-09-04-traffic-analysis-exercise.pcap` | Completed |
| Case 2 | `2024-11-26-traffic-analysis-exercise.pcap` | Completed |
| Case 3 | `2025-06-13-traffic-analysis-exercise.pcap` | Completed |

---

# Main Findings — Case 1

## Suspected Victim

```text
172.17.0.99
```

## Possible C2 Server

```text
79.124.78.197
```

## Suspicious Endpoint

```text
/foots.php
```

## Additional Endpoint

```text
/index.php
```

---

# Key Technical Findings

- Repeated HTTP POST beaconing
- Periodic polling behavior (~60–90 seconds)
- Binary payload exchange (`application/octet-stream`)
- Fake legacy browser User-Agent
- Decoded C2/config response
- Small encrypted/obfuscated beacon payload
- Threat intelligence correlation with KoiLoader/KoiStealer ecosystem

---

# Main Findings — Case 2

## Suspected Victim

```text
10.11.26.183
```

## Possible C2 Server

```text
194.180.191.64
```

## Suspicious Endpoint

```text
/fakeurl.htm
```

## Suspected Malware Family

```text
NetSupport Manager / NetSupport RAT (commercial RAT abuse)
```

---

# Key Technical Findings — Case 2

- Repeated HTTP POST beaconing to direct IP C2
- Periodic polling behavior (~60 seconds, very stable: 60.05–60.29s)
- Encoded payload exchange (`CMD=ENCD · ES=1 · DATA=...`)
- NetSupport Manager/1.3 User-Agent (commercial RAT signature)
- Initial geolocation lookup to `geo.netsupportsoftware.com/location/loca.asp` before first C2 POST
- Body beacon 36-byte identical across posts (SHA256 `975b5678...`)
- MITRE T1219 (Remote Access Software) primary attribution

---

# Main Findings — Case 3

## Suspected Victim

```text
10.6.13.133 (DESKTOP-5AVE44C.massfriction.com)
```

## C2 Infrastructure (Multi-Domain)

```text
event-time-microsoft.org
event-datamicrosoft.live
eventdata-microsoft.live
windows-msgas.com
varying-rentals-calgary-predict.trycloudflare.com  (Cloudflare Tunnel)
```

## Cloudflare Resolved IPs

```text
104.21.16.1, 104.21.24.186, 104.21.64.1, 104.21.80.1, 104.21.96.1, 104.21.112.1
104.16.230.132, 104.16.231.132
```

## Suspected Attack Type

```text
Fileless PowerShell C2 / Modern C2 framework with Cloudflare Tunnel abuse
```

---

# Key Technical Findings — Case 3

- PowerShell-based fileless execution (User-Agent: `WindowsPowerShell/5.1.26100.4202`)
- Multi-domain C2 with Microsoft-typosquatting masquerading
- Cloudflare Tunnel abuse (trycloudflare.com) for origin C2 concealment
- Aggressive beaconing (~30 seconds)
- 968.1 KB obfuscated PowerShell payload (SHA256 `9e2f538c...`)
- Strings: `Invoke-WebRequest`, `Compress-Archive`, `Expand-Archive`, `oauth2.googleapis.com/token`
- URI pattern with 32-char hex substring (encoded exfil indicator)
- MITRE T1059.001, T1071.001, T1090, T1105, T1036, T1102 coverage

---

# Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Manual packet inspection |
| TShark | CLI packet extraction |
| PyShark | Python packet parsing |
| BruteShark | Experimental network analysis |
| PcapXray | PCAP visualization & reporting |
| VirusTotal | Threat intelligence |
| AbuseIPDB | IP reputation lookup |
| AlienVault OTX | IOC enrichment |
| Python | Custom DFIR tooling |
| Docker | Reproducible environment |

---

# Project Structure

```text
network-analysis/
├── docker/
├── notebooks/
├── others/
├── output/
│   ├── case1/
│   │   ├── bruteshark/
│   │   ├── ioc/
│   │   ├── payloads/
│   │   ├── pcapxray/
│   │   ├── pyshark/
│   │   ├── triage/
│   │   ├── visualization/
│   │   │   ├── beacon_timeline.png
│   │   │   ├── communication_graph.png
│   │   │   ├── protocol_pie.png
│   │   │   ├── timeline_heatmap.png
│   │   │   ├── dns_timeline.png
│   │   │   ├── beacon_histogram.png
│   │   │   ├── ioc_heatmap.png
│   │   │   ├── geo_map.html
│   │   │   └── geo_data.csv
│   │   └── zeek_like/
│   ├── case2/  (same structure)
│   ├── case3/  (same structure)
│   ├── visualization/
│   │   └── cross_case_overlap.png
│   ├── cross_case_overlap_stats.csv
│   ├── ioc_coverage_table.csv
│   ├── report_completeness.csv
│   ├── response_variables_summary.md
│   └── master_ioc.csv
├── pcap/
├── reports/
│   ├── case1/
│   ├── case2/
│   └── case3/
├── scripts/
└── tools/
```

---

# Custom DFIR Scripts

| Script | Function |
|---|---|
| `ioc_extractor.py` | IOC extraction dari PCAP |
| `beacon_analysis.py` | Beacon interval analysis |
| `http_payload_extractor.py` | HTTP payload extraction |
| `payload_analyzer.py` | Entropy, strings, signature analysis |
| `zeek_like_logs.py` | Zeek-style normalized logs |
| `beacon_visualization.py` | Beacon timeline visualization |
| `communication_graph.py` | Network communication graph |

---

# Docker Workflow

## Build Docker Image

```bash
docker build -t netforensics docker/
```

## Run Container

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

---

# Example Workflow

## 1. IOC Extraction

```bash
python scripts/ioc_extractor.py
```

## 2. Beacon Analysis

```bash
python scripts/beacon_analysis.py
```

## 3. HTTP Payload Extraction

```bash
python scripts/http_payload_extractor.py
```

## 4. Payload Analysis

```bash
python scripts/payload_analyzer.py
```

## 5. Zeek-like Logging

```bash
python scripts/zeek_like_logs.py
```

## 6. Visualization

```bash
python scripts/beacon_visualization.py
python scripts/communication_graph.py
```

---

# Threat Intelligence Correlation

Threat intelligence enrichment dilakukan menggunakan:

- VirusTotal
- AbuseIPDB
- AlienVault OTX

Case 1 menunjukkan korelasi dengan:

```text
KoiLoader / KoiStealer ecosystem
```

Namun belum ditemukan executable binary utuh sehingga malware identification belum dapat dipastikan secara definitif.

---

# MITRE ATT&CK Mapping

| Technique ID | Technique |
|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1027 | Obfuscated Files or Information |
| T1036 | Masquerading |
| T1105 | Ingress Tool Transfer |

---

# Visualization

## Per-Case Visualizations (8 chart types per case)

| Visualization | Description | Library |
|---|---|---|
| **HTTP Beacon Timeline** | Repeated POST over time | matplotlib |
| **Network Communication Graph** | Host-to-host connection map | NetworkX |
| **Protocol Distribution Pie** | Top 8 protocols + Others | matplotlib |
| **Timeline Activity Heatmap** | Top 15 hosts × minute bins | seaborn |
| **DNS Query Timeline + DGA** | Shannon entropy of SLD vs time | matplotlib |
| **Geographic IP Map (Folium)** | Public IPs plotted on world map | folium + ip-api.com |
| **Beacon Interval Histogram** | Per-host interval distribution | matplotlib |
| **IOC Coverage Heatmap** | Tool × IOC category matrix | seaborn |

Tujuan:
- memperlihatkan beaconing behavior
- memperjelas relasi antar-host
- memperkuat evidence visual pada report
- mendukung DGA detection, geo-location attribution, dan IOC coverage analysis

## Cross-Case Visualizations

| Visualization | Description |
|---|---|
| **Venn Diagram (IP + Domain Overlap)** | 3-set Venn untuk infrastruktur C2 antar case |
| **Master IOC CSV** | Union/intersection semua IOC antar case |

---

# Custom DFIR Scripts

## Core Scripts

| Script | Function |
|---|---|
| `ioc_extractor.py` | IOC extraction dari PCAP |
| `beacon_analysis.py` | Beacon interval analysis |
| `http_payload_extractor.py` | HTTP payload extraction |
| `payload_analyzer.py` | Entropy, strings, signature analysis |
| `zeek_like_logs.py` | Zeek-style normalized logs |
| `beacon_visualization.py` | Beacon timeline visualization |
| `communication_graph.py` | Network communication graph |

## Visualization Scripts (NEW)

| Script | Function |
|---|---|
| `visualize_protocol_pie.py` | Protocol distribution pie chart per case |
| `visualize_timeline_heatmap.py` | Host × time activity heatmap per case |
| `visualize_dns_timeline.py` | DNS query timeline + Shannon entropy DGA detection |
| `visualize_geo_map.py` | Folium geographic IP map (ip-api.com) |
| `visualize_beacon_histogram.py` | Beacon interval histogram per host |
| `visualize_ioc_heatmap.py` | IOC coverage heatmap (tool × category) |
| `visualize_cross_case_overlap.py` | Venn diagram cross-case overlap + master IOC |

## Metrics Script (NEW)

| Script | Function |
|---|---|
| `compute_response_variables.py` | Compute response variables per soal Section 4.3 (IOC count, detection rate, completeness, MITRE coverage) |

## Advanced Analysis Scripts (NEW)

| Script | Function |
|---|---|
| `build_mitre_navigator.py` | Generate MITRE ATT&CK Navigator layer JSON (1 combined layer for 3 cases) - upload to https://mitre-attack.github.io/attack-navigator/ |
| `analyze_tls_ja3.py` | Extract TLS Client Hello, compute JA3 fingerprint per case, build cross-case JA3 comparison |
| `build_file_extraction_summary.py` | Build comprehensive file extraction summary CSV with SHA256, content preview, suspicious flag |

## Report Evidence Script (NEW)

| Script | Function |
|---|---|
| `wireshark_evidence/gen_wireshark_evidence.py` | Generate Wireshark-style evidence PNGs (11 frame captures + Follow TCP Stream) for Lampiran A Final Report. Render dari tshark output via matplotlib — reproducible, headless, verifiable. |

Lihat `scripts/wireshark_evidence/README.md` untuk detail.

# Exploratory DFIR Workflow

Selama proses investigasi, beberapa analisis dilakukan secara exploratory dan iterative menggunakan command-line serta Python inline execution untuk validasi cepat terhadap artefak network traffic.

Pendekatan ini umum digunakan dalam workflow DFIR dan malware traffic analysis, khususnya pada tahap initial investigation dan hypothesis validation.

Setelah metode analisis tervalidasi, proses tersebut kemudian dirapikan menjadi reusable Python scripts agar:

- reproducible
- terdokumentasi
- reusable
- scalable untuk Case 2 dan Case 3

---

# Current Project Status

| Area | Status |
|---|---|
| Initial Triage | Completed |
| IOC Extraction | Completed |
| Beacon Analysis | Completed |
| Payload Extraction | Completed |
| Threat Intel Enrichment | Completed |
| Visualization (8 types/case + cross-case) | Completed |
| Response Variables Computation | Completed |
| TLS/JA3 Fingerprint Analysis | Completed |
| MITRE ATT&CK Navigator Layer | Completed |
| File Extraction Summary | Completed |
| Case 1 Finalization | Completed |
| Case 2 Finalization | Completed |
| Case 3 Finalization | Completed |
| PPT Finalization (64 slides, landscape) | Completed |
| Incident Reports (PDF × 3) | Completed |

## Quantitative Metrics Summary

| Metric | Case 1 | Case 2 | Case 3 |
|---|---|---|---|
| IOC total | 142 | 189 | 222 |
| Files extracted | 6 | 66 | 68 |
| MITRE techniques | 5 | 5 | 8 |
| Analysis time (min) | ~95 | ~80 | ~110 |
| IOC detection rate | 25% | 60% | 70% |
| Report completeness (1-5) | 5/5 | 5/5 | 5/5 |
| DGA detected (entropy >3.5) | 0 | 0 | 23 |

## C2 Geolocation (ip-api.com)

| Case | C2 IP | Country |
|---|---|---|
| 1 | 79.124.78.197 | Bulgaria (Aheloy) |
| 2 | 194.180.191.64 | Netherlands |
| 3 | 104.21.0.0/16 + 104.16.0.0/12 | Cloudflare anycast |

---

# Future Improvements

Planned improvements:

- TLS/JA3 fingerprint analysis
- Comparative analysis antar-case
- Automated IOC correlation
- Advanced visualization
- Additional malware traffic hunting
- SIEM-style normalization

---

# Notes

- Semua payload dianggap suspicious/malicious.
- Payload tidak pernah dijalankan.
- Analisis dilakukan hanya pada level network traffic dan payload characterization.
- Threat intelligence digunakan sebagai enrichment, bukan sebagai single source of truth.

---

# Author

Mini Project — Network Traffic Analysis & DFIR

Environment:
- Docker
- Python
- Wireshark/TShark
- Linux-based forensic workflow

