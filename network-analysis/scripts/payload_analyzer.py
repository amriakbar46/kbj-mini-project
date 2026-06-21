import os
import re
import math
from collections import Counter

PAYLOAD_DIR = "output/week2/http_file_data"

SIGNATURES = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "ZIP archive",
    b"\x1f\x8b": "GZIP archive",
    b"%PDF": "PDF document",
}


def calculate_entropy(data):
    if not data:
        return 0

    counter = Counter(data)

    entropy = 0

    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy


def detect_signature(data):
    for sig, name in SIGNATURES.items():
        if data.startswith(sig):
            return name

    return "Unknown"


def extract_strings(data):
    found = re.findall(rb"[ -~]{4,}", data)
    return [s.decode(errors="ignore") for s in found[:10]]


def hex_preview(data, length=32):
    chunk = data[:length]

    hexs = " ".join(f"{b:02x}" for b in chunk)

    ascii_ = "".join(
        chr(b) if 32 <= b <= 126 else "."
        for b in chunk
    )

    return hexs, ascii_


files = sorted(os.listdir(PAYLOAD_DIR))

for name in files:
    path = os.path.join(PAYLOAD_DIR, name)

    data = open(path, "rb").read()

    entropy = calculate_entropy(data)

    signature = detect_signature(data)

    strings = extract_strings(data)

    hexs, ascii_ = hex_preview(data)

    print("=" * 80)
    print(f"File      : {name}")
    print(f"Size      : {len(data)} bytes")
    print(f"Signature : {signature}")
    print(f"Entropy   : {entropy:.4f}")

    print("\nStrings:")
    if strings:
        for s in strings:
            print(f"  - {s}")
    else:
        print("  (none)")

    print("\nHex Preview:")
    print(hexs)

    print("\nASCII Preview:")
    print(ascii_)
