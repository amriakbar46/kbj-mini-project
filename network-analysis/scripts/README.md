# DFIR Scripts

## Overview

Folder ini berisi custom Python scripts untuk automation dan analisis DFIR pada project network traffic analysis.

---

# Scripts

| Script | Function |
|---|---|
| `ioc_extractor.py` | Extract IOC dari PCAP |
| `beacon_analysis.py` | Analisis beacon interval |
| `http_payload_extractor.py` | Extract HTTP payload |
| `payload_analyzer.py` | Entropy, strings, signature analysis |
| `zeek_like_logs.py` | Generate normalized logs |
| `beacon_visualization.py` | Generate beacon timeline |
| `communication_graph.py` | Generate communication graph |
| `visualize_protocol_pie.py` | Protocol distribution pie chart |
| `visualize_timeline_heatmap.py` | Host × time activity heatmap |
| `visualize_dns_timeline.py` | DNS query timeline + DGA detection |
| `visualize_geo_map.py` | Folium geographic IP map |
| `visualize_beacon_histogram.py` | Beacon interval histogram |
| `visualize_ioc_heatmap.py` | IOC coverage heatmap |
| `visualize_cross_case_overlap.py` | Cross-case Venn diagram |
| `compute_response_variables.py` | Compute report response variables |
| `build_mitre_navigator.py` | Generate MITRE ATT&CK Navigator JSON |
| `analyze_tls_ja3.py` | Extract TLS Client Hello + JA3 fingerprint |
| `build_file_extraction_summary.py` | File extraction summary CSV |
| `wireshark_evidence/gen_wireshark_evidence.py` | Generate Wireshark-style evidence PNGs (Lampiran A Final Report) |

---

# Example Usage

## IOC Extraction

```bash
python scripts/ioc_extractor.py
```

## Beacon Analysis

```bash
python scripts/beacon_analysis.py
```

## Visualization

```bash
python scripts/beacon_visualization.py
python scripts/communication_graph.py
```

## Wireshark Evidence (Lampiran A Final Report)

```bash
python scripts/wireshark_evidence/gen_wireshark_evidence.py
```

Lihat `scripts/wireshark_evidence/README.md` untuk detail filter tshark per PNG.

## Case 3 Deep Analysis Scripts

Lihat `scripts/case3/README.md` untuk 5 script forensic analysis khusus
Case 3 (PE analyzer, config decoder, payload analyzer, YARA validator, VT lookup).
Output artifacts (YARA/Suricata/Sigma rules + VT log + re-analysis memo)
tersimpan di `network-analysis/output/case3/analysis/` (tracked di GitHub).

---

# Notes

- Semua script dibuat untuk workflow DFIR dan malware traffic analysis.
- Script bersifat reusable untuk Case 2 dan Case 3.
- Analisis dilakukan hanya pada level traffic dan payload characterization.
