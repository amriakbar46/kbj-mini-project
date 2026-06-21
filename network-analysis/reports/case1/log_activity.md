# Log Activity — Mini Project Network Traffic Analysis

Tanggal dibuat: 2026-05-17 14:57

## Project

**Mata kuliah:** Komputasi Berbasis Jaringan  
**Topik:** Network Traffic Analysis — Digital Forensics & Incident Response  
**Dataset awal:** Malware Traffic Analysis — 2024-09-04 traffic analysis exercise

---

## 1. Environment Setup

### Host Environment

- OS: Ubuntu Linux
- Wireshark GUI berhasil dijalankan
- TShark berhasil terinstall

Cek TShark:

```bash
tshark -v
```

Hasil:

```text
TShark (Wireshark) 4.2.2
```

### Python Environment

Sebelumnya user memiliki venv sendiri:

```bash
cd ~/Yoan/Kuliah/ITS/python
source gas-kuliah.sh
```

PyShark berhasil dicek:

```bash
python -c "import pyshark; print('OK')"
```

Hasil:

```text
OK
```

---

## 2. Docker Environment

Docker berhasil dites menggunakan:

```bash
sudo docker run hello-world
```

Docker image untuk analisis PCAP dibuat dengan nama:

```text
netforensics
```

### Struktur Project

Folder project:

```text
/home/yoan/Yoan/kuliah/ITS/komputasi-berbasis-jaringan/mini-project-lagi/network-analysis
```

Struktur folder:

```text
network-analysis/
├── docker/
│   ├── Dockerfile
│   └── requirements.txt
├── pcap/
├── scripts/
├── output/
├── notebooks/
└── reports/
```

### Jalankan Docker

Dari root folder project:

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

Catatan:

- `--rm` membuat container otomatis dihapus saat keluar.
- File di `/app` tetap aman karena folder host dimount ke container.
- Output script di `/app/output` akan tersimpan di host pada folder `network-analysis/output`.

### Keluar Docker

```bash
exit
```

---

## 3. Dataset Acquisition

Dataset yang digunakan:

```text
2024-09-04-traffic-analysis-exercise.pcap
```

File berada di:

```text
pcap/2024-09-04-traffic-analysis-exercise.pcap
```

Password ZIP:

```text
infected_20240904
```

### Metadata PCAP

Diperoleh dengan:

```bash
capinfos pcap/2024-09-04-traffic-analysis-exercise.pcap
```

Hasil penting:

```text
File type: pcap
Encapsulation: Ethernet
Number of packets: 5091
Capture duration: 3576.159984 seconds
First packet time: 2024-09-05 00:32:31.318609
Last packet time: 2024-09-05 01:32:07.478593
SHA256: 8fee06d0b1686faab4364f5b7a741e736ad7e713d5ca9299ff9161a4b4d4862e
SHA1: 056c3048beedab5a1aa510bbfd42ef2f6c313a74
```

---

## 4. Wireshark Initial Triage

### 4.1 Protocol Hierarchy

Menu:

```text
Statistics → Protocol Hierarchy
```

Temuan awal:

- TCP dominan
- TLS cukup tinggi
- HTTP terlihat
- SMB/SMB2 terlihat
- LDAP, Kerberos, RPC terlihat

Interpretasi:

```text
Traffic berasal dari environment Windows enterprise / Active Directory.
```

---

### 4.2 Endpoint Analysis

Menu:

```text
Statistics → Endpoints → IPv4
```

Temuan penting:

| IP Address | Interpretasi |
|---|---|
| 172.17.0.99 | suspected infected host / endpoint utama |
| 172.17.0.17 | internal infrastructure / server |
| 79.124.78.197 | possible external C2 |
| 46.254.34.201 | external IP candidate |

---

### 4.3 DNS Analysis

Filter Wireshark:

```text
dns
```

Temuan:

| Item | Value |
|---|---|
| Internal domain | bepositive.com |
| Hostname | DESKTOP-RNV09AT |
| WPAD query | wpad.bepositive.com |

Interpretasi:

```text
DNS menunjukkan Windows Active Directory environment.
```

---

### 4.4 HTTP Analysis

Filter Wireshark:

```text
http.request
```

Temuan utama:

```http
POST /foots.php HTTP/1.1
Host: 79.124.78.197
```

Source dan destination:

```text
172.17.0.99 → 79.124.78.197
```

Interpretasi:

```text
Repeated HTTP POST request mengindikasikan possible malware beaconing / C2 communication.
```

---

### 4.5 Follow HTTP Stream

Menu:

```text
Right click packet → Follow → HTTP Stream
```

Temuan:

```http
POST /foots.php HTTP/1.1
Content-Type: application/octet-stream
Content-Encoding: binary
Host: 79.124.78.197
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; ...)
Server: nginx
```

Interpretasi:

- User-Agent tampak legacy/fake
- Content-Type binary
- Repeated POST
- Possible HTTP-based C2 beaconing

---

## 5. IOC Awal dari Wireshark

| IOC Type | Value | Notes |
|---|---|---|
| Suspected victim | 172.17.0.99 | Internal host aktif |
| Possible C2 | 79.124.78.197 | Destination repeated POST |
| Suspicious URI | /foots.php | Endpoint HTTP POST |
| Internal domain | bepositive.com | AD-like domain |
| Hostname | DESKTOP-RNV09AT | Workstation |
| User-Agent | Mozilla/4.0 MSIE 7.0 | Suspicious legacy UA |
| Content-Type | application/octet-stream | Binary payload |

---

## 6. BruteSharkCli Setup & Evaluation

BruteShark repository dikloning ke:

```text
tools/bruteshark/BruteShark
```

Binary BruteSharkCli diunduh ke:

```text
tools/bruteshark/cli/BruteSharkCli
```

Cek help:

```bash
./BruteSharkCli --help
```

Hasil:

```text
BruteSharkCli 1.0.0.0
Modules: Credentials, FileExtracting, NetworkMap, DNS, Voip
```

### 6.1 Full PCAP Test

Command:

```bash
tools/bruteshark/cli/BruteSharkCli \
-i "pcap/2024-09-04-traffic-analysis-exercise.pcap" \
-m Credentials,DNS,NetworkMap \
-o output/bruteshark-case1
```

Hasil:

```text
ERROR: Failed to process file : 2024-09-04-traffic-analysis-exercise.pcap
```

### 6.2 DNS Module Test

Command:

```bash
tools/bruteshark/cli/BruteSharkCli \
-i "pcap/2024-09-04-traffic-analysis-exercise.pcap" \
-m DNS \
-o output/bruteshark-case1/dns
```

Hasil:

```text
ERROR: Failed to process file : 2024-09-04-traffic-analysis-exercise.pcap
```

### 6.3 Split PCAP Test

Split PCAP:

```bash
editcap -c 1000 \
  pcap/2024-09-04-traffic-analysis-exercise.pcap \
  pcap/case1-split.pcap
```

Test split pertama:

```bash
tools/bruteshark/cli/BruteSharkCli \
-i "pcap/case1-split_00000_20240905003231.pcap" \
-m DNS \
-o output/bruteshark-case1/dns-split
```

Hasil:

```text
ERROR: Failed to process file : case1-split_00000_20240905003231.pcap
```

### Kesimpulan BruteShark

| Metric | Result |
|---|---|
| IOC Count | 0 |
| DNS Extracted | 0 |
| C2 Identified | No |
| Crash / Error | Yes |
| Notes | Failed on full PCAP and split PCAP |

Catatan laporan:

```text
BruteSharkCli gagal memproses PCAP, sedangkan Wireshark berhasil membuka dan menganalisis file. Maka BruteSharkCli dicatat sebagai Crash/Error = Yes untuk case ini.
```

---

## 7. Python / PyShark Automated Extractor

Script dibuat di:

```text
scripts/ioc_extractor.py
```

Jalankan dari dalam Docker:

```bash
python scripts/ioc_extractor.py
```

Output:

```text
output/ioc_case1.csv
output/summary_case1.json
```

### Hasil Summary

| Metric | Result |
|---|---|
| Unique IP Count | 42 |
| DNS Query Count | 39 |
| HTTP Request Count | 57 |
| User-Agent Count | 4 |
| Suspicious POST Count | 49 |

### Protocol Counter Penting

| Protocol | Count |
|---|---|
| TCP | 2681 |
| TLS | 800 |
| QUIC | 331 |
| DNS | 173 |
| LDAP | 150 |
| SMB2 | 135 |
| HTTP | 109 |
| DRSUAPI | 78 |
| DATA | 57 |
| DCERPC | 44 |

### Suspicious POST Evidence

Contoh event:

```json
{
  "method": "POST",
  "host": "79.124.78.197",
  "uri": "/foots.php",
  "src_ip": "172.17.0.99",
  "dst_ip": "79.124.78.197",
  "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; ...)"
}
```

Interpretasi:

```text
Python/PyShark berhasil mengonfirmasi repeated HTTP POST dari 172.17.0.99 ke 79.124.78.197 melalui /foots.php sebanyak 49 suspicious POST request.
```

---

## 8. Laporan HTML

Beberapa report HTML sudah dibuat:

```text
initial-network-analysis-full-report-with-all-screenshots.html
initial-network-analysis-report-updated-bruteshark.html
initial-network-analysis-report-bahasa-indonesia.html
```

Versi terakhir sudah memuat:

- Environment setup
- Dataset acquisition
- Wireshark analysis
- Screenshot evidence
- BruteShark evaluation
- Python/PyShark extractor
- Comparative analysis
- IOC summary
- Beaconing evidence

---

## 9. Checklist PDF — Status

### Sudah

| Requirement | Status |
|---|---|
| Setup environment | Done |
| Download 1 PCAP | Done |
| Initial triage | Done |
| File hash / metadata PCAP | Done |
| Protocol hierarchy | Done |
| Endpoint analysis | Done |
| DNS analysis | Done |
| HTTP analysis | Done |
| Follow HTTP Stream | Done |
| IOC awal | Done |
| BruteShark test | Done, but failed |
| Tool crash/error documented | Done |
| Python/PyShark extraction | Done |
| CSV/JSON IOC output | Done |
| HTML report awal | Done |

### Belum / Partial

| Requirement | Status |
|---|---|
| Minimal 3 PCAP | Belum |
| Minimal 3 tool berbeda per PCAP | Partial |
| PcapXray / TracePcap / packet-capture-analyzer | Belum |
| Zeek log generation | Belum |
| Suricata detection | Belum |
| Threat intelligence enrichment | Belum |
| Malware family identification | Belum |
| File extraction / carving | Belum |
| TLS certificate / JA3 analysis | Belum |
| Beacon interval visualization | Belum |
| Network communication graph | Belum |
| Protocol distribution chart | Belum |
| Timeline activity heatmap | Belum |
| Geographic IP map | Belum |
| MITRE ATT&CK formal table | Partial |
| Cross-case analysis | Belum |
| Final report | Belum |

---

## 10. Current Investigation Summary

### Suspected Victim

```text
172.17.0.99
```

### Possible C2 Server

```text
79.124.78.197
```

### Suspicious URI

```text
/foots.php
```

### Main Behavior

```text
Repeated HTTP POST beaconing
```

### Evidence

- Wireshark HTTP request filter
- Follow HTTP Stream
- PyShark automated extractor
- 49 suspicious POST requests
- Suspicious legacy User-Agent
- Binary content-type

### Initial MITRE Mapping

| Tactic | Technique ID | Technique |
|---|---|---|
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Defense Evasion | T1036 | Masquerading |
| Command and Control | - | Beaconing behavior |

---

## 11. Recommended Next Steps

Prioritas berikutnya:

1. Beacon interval analysis + chart
2. Network communication graph
3. Threat intelligence enrichment untuk `79.124.78.197`
4. Formal MITRE ATT&CK table
5. Coba tool kedua selain BruteShark: Zeek / PcapXray / TracePcap
6. Update laporan HTML
7. Lanjut dataset PCAP kedua
8. Lanjut dataset PCAP ketiga

---

## 12. Important Commands

### Masuk Project

```bash
cd "/home/yoan/Yoan/kuliah/ITS/komputasi-berbasis-jaringan/mini-project-lagi/network-analysis"
```

### Jalankan Docker

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

### Jalankan PyShark Extractor

```bash
python scripts/ioc_extractor.py
```

### Cek Output

```bash
ls -lh output
cat output/summary_case1.json
head output/ioc_case1.csv
```

### Fix File Ownership Jika Ada Gembok

```bash
sudo chown -R $USER:$USER output
```

### Buka Wireshark

```bash
wireshark
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

## 13. Notes

- PCAP aman dianalisis selama tidak menjalankan payload hasil ekstraksi.
- File `.pcap` adalah rekaman traffic, bukan executable.
- Jangan membuka atau menjalankan file hasil export dari PCAP.
- Treat semua payload sebagai malicious.
- BruteShark gagal bukan berarti analisis gagal; justru masuk ke metrik Tool Crash/Error.
