import csv
import subprocess
from pathlib import Path

PCAP = "pcap/2024-09-04-traffic-analysis-exercise.pcap"
TARGET_HOST = "79.124.78.197"

OUT_DIR = Path("output/case1/payloads/c2_flows")
OUT_CSV = OUT_DIR / "http_c2_flow_summary.csv"

OUT_DIR.mkdir(parents=True, exist_ok=True)

fields = [
    "frame.number",
    "frame.time",
    "tcp.stream",
    "ip.src",
    "ip.dst",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.content_length",
    "http.file_data",
]

cmd = [
    "tshark",
    "-r", PCAP,
    "-Y", 'http.request.method == "POST"',
    "-T", "fields",
]

for field in fields:
    cmd.extend(["-e", field])

cmd.extend([
    "-E", "separator=,",
    "-E", "quote=d",
    "-E", "occurrence=f",
])

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode != 0:
    print("tshark error:")
    print(result.stderr)
    raise SystemExit(result.returncode)

rows = []

for line in result.stdout.splitlines():
    if not line.strip():
        continue

    parts = next(csv.reader([line]))
    row = dict(zip(fields, parts))

    # Filter target C2 host in Python for better stability
    if row.get("http.host") != TARGET_HOST:
        continue

    frame = row.get("frame.number", "unknown")
    stream = row.get("tcp.stream", "unknown")
    src = row.get("ip.src", "unknown")
    dst = row.get("ip.dst", "unknown")

    hex_data = row.get("http.file_data", "").replace(":", "").strip()
    decoded_preview = ""
    output_file = ""

    if hex_data:
        try:
            raw = bytes.fromhex(hex_data)

            safe_name = f"frame_{frame}_stream_{stream}_{src}_to_{dst}"
            out_bin = OUT_DIR / f"{safe_name}.bin"
            out_txt = OUT_DIR / f"{safe_name}.txt"

            out_bin.write_bytes(raw)

            decoded_text = raw.decode("utf-8", errors="replace")
            out_txt.write_text(decoded_text, encoding="utf-8", errors="replace")

            decoded_preview = decoded_text[:300]
            output_file = str(out_bin)

        except Exception as exc:
            decoded_preview = f"<decode error: {exc}>"

    row["decoded_preview"] = decoded_preview
    row["output_file"] = output_file
    rows.append(row)

with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=fields + ["decoded_preview", "output_file"]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"saved summary: {OUT_CSV}")
print(f"saved extracted bodies: {OUT_DIR}")
print(f"total POST rows to {TARGET_HOST}: {len(rows)}")

print("\nPreview:")
for row in rows[:10]:
    print(
        f"frame={row.get('frame.number')} "
        f"stream={row.get('tcp.stream')} "
        f"src={row.get('ip.src')} "
        f"dst={row.get('ip.dst')} "
        f"len={row.get('http.content_length')} "
        f"preview={row.get('decoded_preview')[:80]!r}"
    )
