"""Build comprehensive file extraction summary from PCAP analysis.
Includes all HTTP file_data extracted via tshark for 3 cases.
Adds: case, file_path, size, sha256, content_preview, frame_info
"""
import os
import hashlib
import csv
import re
from pathlib import Path

CASES = ["case1", "case2", "case3"]
BASE_DIR = "output"

OUTPUT = "output/file_extraction_summary.csv"


def sha256_of_file(path):
    """Compute SHA256 of file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def content_preview(path, max_len=80):
    """Read first N bytes as ASCII-ish preview."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_len)
        # Try to decode, replace non-printable
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        # Replace non-printable
        preview = "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in text)
        return preview[:max_len]
    except Exception:
        return ""


def detect_content_type(path):
    """Detect content type from filename and content."""
    fname = os.path.basename(path)
    if "octet-stream" in fname or "stream" in fname:
        return "application/octet-stream"
    if "c2_flow" in path or "frame_" in fname:
        return "binary/network-artifact"
    if ".txt" in fname or ".tsv" in fname or ".csv" in fname:
        return "text/plain"
    if ".png" in fname or ".jpg" in fname:
        return "image"
    # Check content
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        if head[:2] == b"\x4d\x4d":
            return "image/big-tiff"
        if head[:2] == b"\x89\x50":
            return "image/png"
        if head[:2] == b"\xff\xd8":
            return "image/jpeg"
        if head[:4] == b"\x50\x4b\x03\x04":
            return "application/zip"
        if head[:2] == b"MZ":
            return "application/x-executable"
        if head[:4] == b"%PDF":
            return "application/pdf"
        if b"HTTP" in head[:20]:
            return "text/http"
    except Exception:
        pass
    return "unknown"


def extract_frame_info(fname):
    """Extract frame/stream info from filename like 'frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin'."""
    m = re.search(r"frame_(\d+)_stream_(\d+)_([\d\.]+)_to_([\d\.]+)", fname)
    if m:
        return {
            "frame_number": int(m.group(1)),
            "tcp_stream": int(m.group(2)),
            "src_ip": m.group(3),
            "dst_ip": m.group(4),
        }
    return {"frame_number": 0, "tcp_stream": 0, "src_ip": "", "dst_ip": ""}


def is_suspicious(path, size, content_preview, case):
    """Heuristic: is this file suspicious?"""
    if case == "case1":
        # Koi-like: C2 flows
        if "/c2_flows/" in path or "_101_" in path or "_111_" in path or "_102_" in path:
            return "yes"
        return "no"
    elif case == "case2":
        # NetSupport: CMD=ENCD body
        if b"CMD=ENCD" in content_preview.encode()[:80] if content_preview else False:
            return "yes"
        if "/c2_flows/" in path and "_77_" in path:
            return "yes"
        if "ES=1" in content_preview or "DATA=" in content_preview:
            return "yes"
        return "no"
    else:  # case3
        # PowerShell
        if "$" in content_preview and ("Invoke-" in content_preview or "Get-" in content_preview):
            return "yes"
        if "/c2_flows/" in path and "_90_" in path:
            return "yes"
        return "no"


def build_summary():
    rows = []
    for case in CASES:
        case_dir = f"{BASE_DIR}/{case}"
        if not os.path.isdir(case_dir):
            continue
        # Walk all subdirs to find files
        for root, dirs, files in os.walk(case_dir):
            for fname in sorted(files):
                # Skip large files like all_http_file_data.tsv (we want per-file records)
                if fname == "all_http_file_data.tsv":
                    continue
                if fname.endswith(".png") or fname.endswith(".html"):
                    continue  # Skip visualization images/maps
                fpath = os.path.join(root, fname)
                # Get file info
                rel_path = os.path.relpath(fpath, BASE_DIR)
                if not os.path.isfile(fpath):
                    continue
                size = os.path.getsize(fpath)
                sha256 = sha256_of_file(fpath)
                preview = content_preview(fpath)
                ctype = detect_content_type(fpath)
                finfo = extract_frame_info(fname)
                susp = is_suspicious(fpath, size, preview, case)
                rows.append({
                    "case": case,
                    "file_path": rel_path,
                    "file_name": fname,
                    "size_bytes": size,
                    "sha256": sha256,
                    "content_type": ctype,
                    "content_preview": preview,
                    "frame_number": finfo["frame_number"],
                    "tcp_stream": finfo["tcp_stream"],
                    "src_ip_in_filename": finfo["src_ip"],
                    "dst_ip_in_filename": finfo["dst_ip"],
                    "suspicious_flag": susp,
                })

    # Write CSV
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", newline="") as f:
        if not rows:
            return
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # Print summary
    print(f"[OK] {OUTPUT}")
    print(f"     Total files: {len(rows)}")
    from collections import Counter
    by_case = Counter(r["case"] for r in rows)
    for c in CASES:
        n = by_case.get(c, 0)
        susp_n = sum(1 for r in rows if r["case"] == c and r["suspicious_flag"] == "yes")
        print(f"     {c}: {n} files ({susp_n} suspicious)")


if __name__ == "__main__":
    build_summary()
