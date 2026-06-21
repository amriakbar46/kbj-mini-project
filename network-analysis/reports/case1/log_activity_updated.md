# Log Activity — Mini Project Network Traffic Analysis

Tanggal update: 2026-05-24

## Update Progress — Week 2

### Progress Investigasi Saat Ini

Investigasi berhasil mengidentifikasi indikasi kuat adanya aktivitas Command and Control (C2) berbasis HTTP beaconing dari host internal menuju external IP.

#### Suspected Victim

```text
172.17.0.99
```

#### Possible C2 Server

```text
79.124.78.197
```

#### Suspicious URI

```text
/foots.php
```

#### Evidence Utama

- Repeated HTTP POST request
- Binary payload (`application/octet-stream`)
- Legacy/suspicious User-Agent
- Repeated communication pattern
- Confirmed oleh Wireshark dan PyShark extractor

---

## Additional Analysis Notes

### Beaconing Behavior

Behavior berikut dianggap suspicious karena:

- Interval komunikasi terlihat repetitif
- HTTP POST dilakukan berulang
- Menggunakan endpoint `.php`
- User-Agent menyerupai browser lama/fake
- Content-Encoding binary

Indikasi tersebut sesuai pola malware beaconing/C2 communication.

---

## Initial DFIR Assessment

### Initial Triage

Triage awal dilakukan menggunakan:

- Wireshark
- TShark
- PyShark
- BruteSharkCli

### Outcome

| Tool | Result |
|---|---|
| Wireshark | Success |
| TShark | Success |
| PyShark | Success |
| BruteSharkCli | Failed/Error |

---

## MITRE ATT&CK Initial Mapping

| Tactic | Technique ID | Technique |
|---|---|---|
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Defense Evasion | T1036 | Masquerading |
| Command and Control | - | Beaconing Behavior |

### Alasan Mapping

#### T1071.001 — Web Protocols

Karena malware menggunakan komunikasi HTTP POST untuk berkomunikasi dengan external server.

#### T1036 — Masquerading

Karena User-Agent dibuat menyerupai browser legitimate lama:

```text
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)
```

---

## Current Evidence Summary

| Evidence | Description |
|---|---|
| HTTP POST | Repeated POST request |
| URI | `/foots.php` |
| Destination IP | `79.124.78.197` |
| Payload Type | `application/octet-stream` |
| User-Agent | Legacy/fake browser UA |
| Request Count | 49 suspicious POST requests |

---

## Recommended Next Steps

Prioritas analisis berikutnya:

1. Beacon interval analysis
2. Communication graph visualization
3. Zeek log generation
4. Threat intelligence enrichment
5. TLS/JA3 analysis
6. Formal MITRE ATT&CK table
7. Analisis PCAP kedua
8. Analisis PCAP ketiga

---

## Important Commands

### Jalankan Docker

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

### Jalankan IOC Extractor

```bash
python scripts/ioc_extractor.py
```

### Wireshark Filters

```text
dns
http.request
http.request.method == "POST"
tls
ip.addr == 172.17.0.99
ip.addr == 79.124.78.197
```

---

## Notes

- PCAP aman dianalisis selama payload tidak dijalankan.
- Semua payload dianggap malicious.
- BruteShark failure tetap valid sebagai evaluasi tool.
- Evidence saat ini cukup kuat untuk indikasi malware beaconing / C2 communication.
