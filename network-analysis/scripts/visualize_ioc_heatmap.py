import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import sys
import os
import re

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

IOC_CSV = {
    "case1": "output/case1/ioc/ioc_case1.csv",
    "case2": "output/case2/ioc/ioc_case2.csv",
    "case3": "output/case3/ioc/ioc_case3.csv",
}

OUTPUT = {
    "case1": "output/case1/visualization/ioc_heatmap.png",
    "case2": "output/case2/visualization/ioc_heatmap.png",
    "case3": "output/case3/visualization/ioc_heatmap.png",
}

# Tools (per case, ground truth from incident reports Section 6)
# Case 1: NetworkMiner included (artifact from team member)
# Case 2 & 3: only Wireshark + Python/Zeek-like (murni script custom)
TOOLS = ["BruteShark", "Wireshark/TShark", "Python/Zeek-like"]

# Category matrix per case (1=Detected, 0=Not detected/Partial)
# Based on Incident Report Section 6 (IOC Coverage per Tool)
def get_matrix(case):
    # case 1: HTTP beacon, Foots.php/Index.php, MSIE UA, Adobe LoTS
    # case 2: NetSupport RAT, fakeurl.htm, NetSupport UA, Adobe LoTS
    # case 3: PowerShell C2, multi-domain, PowerShell UA, WSDAPI
    if case == "case1":
        return {
            "BruteShark":         {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1, "C2": 1},
            "Wireshark/TShark":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1, "C2": 1},
            "NetworkMiner":       {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1, "C2": 1},
            "Python/Zeek-like":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1, "C2": 1},
        }
    elif case == "case2":
        return {
            "BruteShark":         {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1, "C2": 1},
            "Wireshark/TShark":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1, "C2": 1},
            "Python/Zeek-like":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1, "C2": 1},
        }
    else:  # case 3
        return {
            "BruteShark":         {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1, "C2": 1},
            "Wireshark/TShark":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 1, "UA": 1, "C2": 1},
            "Python/Zeek-like":   {"IP": 1, "Domain": 1, "URL": 1, "Hash": 0, "UA": 1, "C2": 1},
        }

# Compute actual IOC count from CSV
def count_iocs(case):
    counts = {"IP": 0, "Domain": 0, "URL": 0, "Hash": 0, "UA": 0}
    if not os.path.exists(IOC_CSV[case]):
        return counts
    with open(IOC_CSV[case]) as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = row["ioc_type"]
            if t == "ip":
                counts["IP"] += 1
            elif t == "domain":
                counts["Domain"] += 1
            elif t == "url":
                counts["URL"] += 1
            elif t == "user_agent":
                counts["UA"] += 1
            elif t == "hash":
                counts["Hash"] += 1
    return counts

categories = ["IP", "Domain", "URL", "Hash", "UA", "C2"]
matrix = get_matrix(CASE)
counts = count_iocs(CASE)

# Build 2D matrix: rows=tools, cols=categories
data = np.array([[matrix[t][c] for c in categories] for t in TOOLS])

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5), dpi=110, gridspec_kw={"width_ratios": [2, 1]})

# Heatmap: coverage (binary)
im = ax1.imshow(data, aspect="auto", cmap="RdYlGn", vmin=0, vmax=1)
ax1.set_xticks(range(len(categories)))
ax1.set_xticklabels(categories, fontsize=10)
ax1.set_yticks(range(len(TOOLS)))
ax1.set_yticklabels(TOOLS, fontsize=10)
ax1.set_title(f"IOC Coverage Matrix (1=Detected, 0=Not)\n{CASE.upper()}", fontsize=12, fontweight="bold")
for i in range(len(TOOLS)):
    for j in range(len(categories)):
        text_color = "white" if data[i, j] == 0 else "black"
        ax1.text(j, i, "✓" if data[i, j] == 1 else "✗",
                 ha="center", va="center", color=text_color, fontsize=14, fontweight="bold")
cbar = plt.colorbar(im, ax=ax1, fraction=0.05)
cbar.set_ticks([0, 1])
cbar.set_ticklabels(["Not Detected", "Detected"])

# Bar chart: actual IOC counts
cats_no_c2 = ["IP", "Domain", "URL", "Hash", "UA"]
vals = [counts[c] for c in cats_no_c2]
ax2.barh(cats_no_c2[::-1], vals[::-1], color="#1d5d8f", alpha=0.85)
for i, v in enumerate(vals[::-1]):
    ax2.text(v + max(vals) * 0.01, i, str(v), va="center", fontsize=10, fontweight="bold")
ax2.set_xlabel("Count (from IOC CSV)", fontsize=10)
ax2.set_title(f"Total IOC Count per Category\n{CASE.upper()}", fontsize=12, fontweight="bold")
ax2.grid(True, alpha=0.3, axis="x", linestyle="--")

plt.tight_layout()
plt.savefig(OUTPUT[CASE], bbox_inches="tight", dpi=110)
plt.close()
print(f"[OK] Saved {OUTPUT[CASE]} — counts: IP={counts['IP']}, Domain={counts['Domain']}, URL={counts['URL']}, Hash={counts['Hash']}, UA={counts['UA']}")
