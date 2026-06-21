"""Build cross-case IOC detection rate per tool breakdown.
For each case, estimate IOC detection rate by tool from the Section 6 matrix in incident reports.
"""
import csv

CASES = ["case1", "case2", "case3"]
OUT = "output/ioc_detection_per_tool.csv"

# Per-case, per-tool, per-category detection matrix (1=detected, 0=not)
# Based on Section 6 of each incident report
TOOL_MATRIX = {
    "case1": {
        "BruteShark":       {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1},
        "Wireshark/TShark": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1},
        "NetworkMiner":     {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1},
        "Python/Zeek-like": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1},
    },
    "case2": {
        "BruteShark":       {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1},
        "Wireshark/TShark": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1},
        "Python/Zeek-like": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1},
    },
    "case3": {
        "BruteShark":       {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1},
        "Wireshark/TShark": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1},
        "Python/Zeek-like": {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1},
    },
}

CATS = ["IP", "Domain", "URL", "Hash", "UA"]
# Tools list — NetworkMiner only in case 1
TOOLS_PER_CASE = {
    "case1": ["BruteShark", "Wireshark/TShark", "NetworkMiner", "Python/Zeek-like"],
    "case2": ["BruteShark", "Wireshark/TShark", "Python/Zeek-like"],
    "case3": ["BruteShark", "Wireshark/TShark", "Python/Zeek-like"],
}


def main():
    rows = []
    # For each case, for each tool, compute detection %
    for case in CASES:
        for tool in TOOLS_PER_CASE[case]:
            detected = sum(TOOL_MATRIX[case][tool][c] for c in CATS)
            total_cats = len(CATS)
            detection_pct = (detected / total_cats) * 100
            rows.append({
                "case": case,
                "tool": tool,
                "ip_detected": TOOL_MATRIX[case][tool]["IP"],
                "domain_detected": TOOL_MATRIX[case][tool]["Domain"],
                "url_detected": TOOL_MATRIX[case][tool]["URL"],
                "hash_detected": TOOL_MATRIX[case][tool]["Hash"],
                "ua_detected": TOOL_MATRIX[case][tool]["UA"],
                "categories_detected": detected,
                "categories_total": total_cats,
                "detection_pct": round(detection_pct, 1),
            })

    # Write CSV
    with open(OUT, "w", newline="") as f:
        if not rows:
            return
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[OK] Saved {OUT} ({len(rows)} rows)")

    # Print summary
    print("\n=== Per-tool detection rate summary ===")
    print(f"{'Case':<10} | {'Tool':<22} | {'Detection':<10}")
    print("-" * 50)
    for r in rows:
        print(f"{r['case']:<10} | {r['tool']:<22} | {r['detection_pct']:>5.1f}% ({r['categories_detected']}/{r['categories_total']})")

    # Average per tool across cases
    print("\n=== Average detection rate per tool (3 cases) ===")
    from collections import defaultdict
    tool_avg = defaultdict(list)
    for r in rows:
        tool_avg[r["tool"]].append(r["detection_pct"])
    for tool in ["BruteShark", "Wireshark/TShark", "NetworkMiner", "Python/Zeek-like"]:
        if tool in tool_avg:
            avg = sum(tool_avg[tool]) / len(tool_avg[tool])
            print(f"  {tool:<22}: {avg:.1f}%")


if __name__ == "__main__":
    main()
