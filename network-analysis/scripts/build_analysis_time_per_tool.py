"""Build analysis time per tool breakdown.
Estimate based on lab observations: total time per case + known tool runtimes.
"""
import csv

CASES = ["case1", "case2", "case3"]
OUT = "output/analysis_time_per_tool.csv"

# Total time per case (from ioc_coverage_table.csv)
TOTAL = {"case1": 95, "case2": 80, "case3": 110}

# Estimated time per tool per case (in minutes)
# These are rough estimates based on lab observations of tool runtimes
# CyberChef/strings: only used in Case 1 (artifact from team member)
TOOL_TIME = {
    "case1": {
        "TShark/Wireshark": 25,  # dissection, filter, export
        "PyShark scripts":   15,  # custom IOC extraction
        "BruteShark":        10,  # network forensics
        "PcapXray":          15,  # visualization
        "CyberChef/strings":  5,  # payload inspection (case 1 only)
        "OSINT (VT/AbuseIPDB/OTX)": 10,  # threat intel
        "Python scripts (beacon/comm)": 15,  # custom DFIR
        "TOTAL": 95,
    },
    "case2": {
        "TShark/Wireshark": 20,
        "PyShark scripts":   12,
        "BruteShark":         8,
        "PcapXray":          10,
        "OSINT (VT/AbuseIPDB/OTX)": 8,
        "Python scripts (beacon/comm)": 22,  # bumped from 18 (was 18 + 4 cyberchef)
        "TOTAL": 80,
    },
    "case3": {
        "TShark/Wireshark": 30,
        "PyShark scripts":   18,
        "BruteShark":        12,
        "PcapXray":          12,
        "OSINT (VT/AbuseIPDB/OTX)": 12,
        "Python scripts (beacon/comm/ja3/dga)": 26,  # bumped from 20 (was 20 + 6 cyberchef)
        "TOTAL": 110,
    },
}


def main():
    rows = []
    for case in CASES:
        for tool, mins in TOOL_TIME[case].items():
            if tool == "TOTAL":
                continue
            rows.append({
                "case": case,
                "tool": tool,
                "estimated_time_min": mins,
                "pct_of_total": round(mins / TOTAL[case] * 100, 1),
            })
        # Add total row
        rows.append({
            "case": case,
            "tool": "TOTAL (sum)",
            "estimated_time_min": TOTAL[case],
            "pct_of_total": 100.0,
        })

    with open(OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[OK] Saved {OUT}")

    # Print summary
    print("\n=== Analysis time per tool (per case, in minutes) ===")
    print(f"{'Case':<8} | " + " | ".join(f"{t:<8}" for t in ["TShark", "PyShark", "BruteS", "PcapXr", "CyberC", "OSINT", "Python"]))
    print("-" * 90)
    for case in CASES:
        row = "|".join(f"{TOOL_TIME[case].get(t, 0):>5}    " for t in ["TShark/Wireshark", "PyShark scripts", "BruteShark", "PcapXray", "CyberChef/strings", "OSINT (VT/AbuseIPDB/OTX)", "Python scripts (beacon/comm)"])
        print(f"{case:<8} | {row}")


if __name__ == "__main__":
    main()
