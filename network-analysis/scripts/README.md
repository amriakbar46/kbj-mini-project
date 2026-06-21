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

---

# Notes

- Semua script dibuat untuk workflow DFIR dan malware traffic analysis.
- Script bersifat reusable untuk Case 2 dan Case 3.
- Analisis dilakukan hanya pada level traffic dan payload characterization.
