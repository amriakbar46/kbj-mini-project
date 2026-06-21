# Wireshark Evidence Generator

Script untuk men-generate screenshot bukti Wireshark untuk lampiran Final Report.

## Apa ini?

`gen_wireshark_evidence.py` membuat PNG yang mirip packet-list pane Wireshark dari output `tshark`. Output PNG dipakai di **Lampiran A (Section 11)** Final Report sebagai screenshot bukti untuk frame-frame penting.

Folder ini berisi:
- `gen_wireshark_evidence.py` — script generator
- `output/` — 35 PNG hasil generator + visualisasi pendukung (tracked di GitHub)

## Kenapa render dari tshark, bukan screenshot Wireshark GUI?

- **Reproducible**: jalankan ulang script dengan PCAP yang sama → PNG identik (kecuali timestamp).
- **Headless**: jalan di Linux tanpa display server (Wireshark GUI butuh X11).
- **Verifiable**: setiap cell di PNG sesuai dengan field tshark. Pembaca bisa re-derive pakai command tshark yang tertera di title bar PNG.
- **Self-documenting**: title bar PNG menunjukkan filter `tshark -Y` yang dipakai, sehingga bisa langsung di-cross-check.

## Dependensi

- `tshark` (Wireshark CLI)
- Python 3.8+
- `matplotlib`

## Cara pakai

Dari folder repo root:

```bash
# Default: output ke folder output/ (tracked di GitHub)
python3 network-analysis/scripts/wireshark_evidence/gen_wireshark_evidence.py

# Custom output dir (mis. untuk render ulang ke folder report)
python3 network-analysis/scripts/wireshark_evidence/gen_wireshark_evidence.py \
  --out-dir docs/final\ submit/edited\ final/wireshark_evidence
```

Script men-generate 11 PNG baru ke `output/` (overwrite yang existing):
- `case1_c2_http_beacon.png` — semua HTTP request ke C2 Bulgaria
- `case1_follow_stream.png` — Follow TCP Stream POST `/foots.php`
- `case2_c2_http_beacon.png` — semua HTTP request ke C2 Moldova
- `case2_follow_stream.png` — Follow TCP Stream NetSupport POST
- `case3_initial_stager.png` — frame 6642 (GET) + 6699 (POST initial stager)
- `case3_byoi_tls.png` — frame 8569 (TLS ke windows.php.net)
- `case3_first_c2_beacon.png` — frame 44292 (POST windows-msgas.com, no UA)
- `case3_multi_domain_c2.png` — rotasi 3 C2 domain
- `case3_dns_c2_queries.png` — DNS query ke 6 domain
- `case3_wsdapi_benign.png` — WSDAPI POST (benign, negative evidence)
- `case3_follow_stream_stager.png` — Follow TCP Stream 89 (initial stager)
- `case3_follow_stream_c2_beacon.png` — Follow TCP Stream first C2 beacon

20 PNG lain di `output/` (visualisasi pendukung: `*_communication_graph.png`, `*_beacon_histogram.png`, `*_protocol_pie.png`, `*_timeline_heatmap.png`, `*_dns_timeline.png`, `*_ioc_heatmap.png`, `*_geo_map_screenshot.png`, `cross_case_overlap.png`) di-generate oleh script viz lain di `network-analysis/scripts/` (lihat folder parent). Disimpan di sini juga supaya semua visualisasi Final Report terpusat di satu folder.

## Verifikasi

Setiap PNG menampilkan command `tshark` di title bar. Untuk cross-check cell tertentu:

```bash
# Contoh: verify frame 8569
tshark -r network-analysis/pcap/2025-06-13-traffic-analysis-exercise.pcap \
  -Y "frame.number == 8569" \
  -T fields -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e _ws.col.Protocol \
  -e tls.handshake.extensions_server_name
```

Output harus match dengan yang ada di `output/case3_byoi_tls.png`.

## Filter tshark yang dipakai

| File | Filter |
|------|--------|
| `case1_c2_http_beacon.png` | `http.request and ip.dst == 79.124.78.197` |
| `case2_c2_http_beacon.png` | `http.request and ip.dst == 194.180.191.64` |
| `case3_initial_stager.png` | `frame.number == 6642 or frame.number == 6699` |
| `case3_byoi_tls.png` | `frame.number == 8569` |
| `case3_first_c2_beacon.png` | `http.request and http.host == "windows-msgas.com" and frame.number < 45000` |
| `case3_multi_domain_c2.png` | `http.request and (host matches 3 C2 domains)` |
| `case3_dns_c2_queries.png` | `dns.qry.name matches (3 C2 + 2 stager + BYOI)` |
| `case3_wsdapi_benign.png` | `http.request and ip.dst == 10.6.13.129` |

Lihat source code untuk filter lengkap per PNG.
