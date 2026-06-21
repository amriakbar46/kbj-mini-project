"""Build tool-specific output stats for PPT slide.
Aggregates per-tool output statistics for the 3 PCAP cases:
- BruteShark (bruteshark): file count per case
- PcapXray (pcapxray): file count per case
- PyShark (pyshark): summary lines per case
- Zeek-like (zeek_like): row counts per case
"""
import os
import csv

CASES = ["case1", "case2", "case3"]
OUTPUT = "output/tool_output_stats.json"


def count_files_in_dir(d):
    """Count files in dir, excluding empty subdirs."""
    if not os.path.isdir(d):
        return 0
    count = 0
    for root, dirs, files in os.walk(d):
        for f in files:
            count += 1
    return count


def count_csv_rows(path):
    """Count data rows (excluding header) in CSV."""
    if not os.path.isfile(path):
        return 0
    try:
        with open(path) as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            return sum(1 for _ in reader)
    except Exception:
        return 0


def build():
    stats = {"generated_at": __import__("datetime").datetime.now().isoformat(), "cases": {}}

    for case in CASES:
        case_stats = {
            "bruteshark": {
                "file_count": count_files_in_dir(f"output/{case}/bruteshark"),
                "extracted_files_per_category": {
                    "dns": count_files_in_dir(f"output/{case}/bruteshark/bruteshark-{case}/dns/Files"),
                    "files": count_files_in_dir(f"output/{case}/bruteshark/bruteshark-{case}/files/Files"),
                    "parameters": count_files_in_dir(f"output/{case}/bruteshark/bruteshark-{case}/parameters/Files"),
                },
                "iocs_extracted": "Yes (DNS, HTTP, files)",
            },
            "pcapxray": {
                "file_count": count_files_in_dir(f"output/{case}/pcapxray"),
                "visual_artifact": "Communication graph PNG, session DB",
                "iocs_extracted": "Host/port summary from PCAP visualization",
            },
            "pyshark": {
                "summary_file": f"output/{case}/pyshark/{['2024-09-04', '2024-11-26', '2025-06-13'][CASES.index(case)]}-summary.txt",
                "file_count": count_files_in_dir(f"output/{case}/pyshark"),
                "summary_line_count": 0,
                "iocs_extracted": "DNS, HTTP, SMB stats",
            },
            "zeek_like": {
                "file_count": count_files_in_dir(f"output/{case}/zeek_like"),
                "conn_summary_rows": count_csv_rows(f"output/{case}/zeek_like/conn_summary.csv"),
                "dns_summary_rows": count_csv_rows(f"output/{case}/zeek_like/dns_summary.csv"),
                "http_summary_rows": count_csv_rows(f"output/{case}/zeek_like/http_summary.csv"),
                "suspicious_http_rows": count_csv_rows(f"output/{case}/zeek_like/suspicious_http.csv"),
                "iocs_extracted": "Normalised conn log, DNS queries, HTTP requests",
            },
        }

        # PyShark line count
        psh_path = case_stats["pyshark"]["summary_file"]
        if os.path.isfile(psh_path):
            try:
                with open(psh_path) as f:
                    case_stats["pyshark"]["summary_line_count"] = sum(1 for _ in f)
            except Exception:
                pass

        stats["cases"][case] = case_stats

    # Cross-case summary
    stats["cross_case_summary"] = {}
    for tool in ["bruteshark", "pcapxray", "pyshark", "zeek_like"]:
        total = 0
        for case in CASES:
            try:
                total += stats["cases"][case][tool]["file_count"]
            except KeyError:
                print(f"[DEBUG] Missing key for {case}/{tool}: keys = {list(stats['cases'][case][tool].keys())}")
                raise
        stats["cross_case_summary"][tool + "_files"] = total

    # PyShark line count separately
    total = 0
    for case in CASES:
        total += stats["cases"][case]["pyshark"]["summary_line_count"]
    stats["cross_case_summary"]["pyshark_summary_lines"] = total

    # Zeek-like row totals
    for k in ["conn_summary_rows", "dns_summary_rows", "http_summary_rows", "suspicious_http_rows"]:
        total = 0
        for case in CASES:
            total += stats["cases"][case]["zeek_like"].get(k, 0)
        stats["cross_case_summary"]["zeek_like_" + k] = total

    with open(OUTPUT, "w") as f:
        import json
        json.dump(stats, f, indent=2)
    print(f"[OK] Saved {OUTPUT}")
    return stats


if __name__ == "__main__":
    stats = build()
    print("\n=== Cross-case tool output summary ===")
    for tool, total in stats["cross_case_summary"].items():
        print(f"  {tool}: {total}")
