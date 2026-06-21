# Case 3 Forensic Analysis Scripts

Python scripts for static analysis and detection engineering of the
Case 3 (2025-06-13) BYOI PHP RAT forensic bundle.

## Scripts

| Script | Purpose | Input |
|---|---|---|
| `case3_pe_analyzer.py` | Full PE static analysis (hashes, sections, imports, entropy, strings) | `c2.exe` |
| `case3_config_decoder.py` | Decode obfuscated PHP RAT config (hex escapes, functions, command codes, XOR constants) | `config.cfg` |
| `case3_payload_analyzer.py` | Analyze 968 KB payload from PCAP stream 90 (entropy, patterns, base64 decode) | `frame_8561_stream_90_*.bin` |
| `case3_yara_validator.py` | Validate YARA rules against all bundle files | `.yar` + bundle dir |
| `case3_vt_lookup.py` | VirusTotal API lookup for family attribution | API key + files |

## Setup

```bash
# Install dependencies (run once)
pip3 install --break-system-packages pefile yara-python vt-py

# VirusTotal API key setup
cd network-analysis
cp .env.template .env
# Edit .env and replace YOUR_VIRUSTOTAL_API_KEY_HERE with your actual key
# Get free key from: https://www.virustotal.com/gui/user/[username]/apikey
```

## Usage

```bash
# From project root
cd /home/yoan/Yoan/kuliah/ITS/komputasi-berbasis-jaringan\ /mini-project-lagi

# 1. PE analysis
python3 network-analysis/scripts/case3/case3_pe_analyzer.py \
  network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/AppData-Roaming-afUGkp/c2.exe

# 2. Config decoder
python3 network-analysis/scripts/case3/case3_config_decoder.py \
  network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/AppData-Roaming-php/config.cfg

# 3. Payload analyzer
python3 network-analysis/scripts/case3/case3_payload_analyzer.py \
  network-analysis/output/case3/payloads/http_file_data/frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin

# 4. YARA validator
python3 network-analysis/scripts/case3/case3_yara_validator.py \
  network-analysis/output/case3/analysis/yara_rules.yar \
  network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/ \
  network-analysis/

# 5. VirusTotal lookup (requires API key in .env)
python3 network-analysis/scripts/case3/case3_vt_lookup.py
```

## API Key Rotation (IMPORTANT)

Your VirusTotal API key is stored in `network-analysis/.env` and is
git-ignored. If the key has been exposed (e.g., in chat history, logs, or
accidental commits), rotate it:

1. Go to https://www.virustotal.com/gui/user/[username]/apikey
2. Click "Regenerate API key"
3. Update `network-analysis/.env` with the new key
4. Delete old log files that may contain the old key (the API key
   in `network-analysis/output/case3/analysis/vt_lookup_log.txt` is
   already redacted to `7c63a538...7b468e95` for safe public sharing)

Free tier limits: 4 lookups/min, 500/day, 15.5K/month.

## Output Artifacts (tracked in `network-analysis/output/case3/analysis/`)

All detection-engineering artifacts are committed to the repo at
`network-analysis/output/case3/analysis/`:

| File | Content |
|---|---|
| `yara_rules.yar` | 4 YARA rules (validated, 3 match against forensic bundle) |
| `suricata.rules` | 18 Suricata rules (sid 9300001–9300018, all compiled) |
| `sigma_rules.yml` | 7 Sigma rules for SIEM |
| `vt_lookup_log.txt` | Full VirusTotal lookup result log (API key redacted) |
| `REANALYSIS_MEMO.md` | Full re-analysis memo (4 iteration, 44 KB) |

The HTML report and PDF are kept locally under `docs/` (gitignored) since
they are draft-only artifacts. The committed artifacts in
`output/case3/analysis/` are the **final deliverables** referenced from
the Final Report Lampiran A.
