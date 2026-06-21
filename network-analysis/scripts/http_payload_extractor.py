import os

# case 1
#INPUT_FILE = "output/case1/payloads/all_http_file_data.tsv"
#OUTPUT_DIR = "output/case1/payloads/http_file_data"

#case 2
#INPUT_FILE = "output/case2/payloads/all_http_file_data.tsv"
#OUTPUT_DIR = "output/case2/payloads/http_file_data"

#case 3
INPUT_FILE = "output/case3/payloads/all_http_file_data.tsv"
OUTPUT_DIR = "output/case3/payloads/http_file_data"


os.makedirs(OUTPUT_DIR, exist_ok=True)

extracted = 0

with open(INPUT_FILE, "r", errors="ignore") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")

        if len(parts) < 5:
            continue

        frame, stream, src, dst, hexdata = parts[:5]

        hexdata = hexdata.replace(":", "").strip()

        if not hexdata or hexdata == "<MISSING>":
            continue

        try:
            data = bytes.fromhex(hexdata)
        except ValueError:
            continue

        filename = (
            f"frame_{frame}_stream_{stream}_"
            f"{src}_to_{dst}.bin"
        )

        outpath = os.path.join(OUTPUT_DIR, filename)

        with open(outpath, "wb") as wf:
            wf.write(data)

        print(f"[+] Extracted: {filename} ({len(data)} bytes)")
        extracted += 1

print(f"\nDone. Total extracted payloads: {extracted}")
