import pyshark
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import math
import sys
import subprocess
import json
import os
import re
from collections import defaultdict, Counter

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

PCAP_PATHS = {
    "case1": "pcap/2024-09-04-traffic-analysis-exercise.pcap",
    "case2": "pcap/2024-11-26-traffic-analysis-exercise.pcap",
    "case3": "pcap/2025-06-13-traffic-analysis-exercise.pcap",
}

OUTPUT = {
    "case1": "output/case1/visualization/dns_timeline.png",
    "case2": "output/case2/visualization/dns_timeline.png",
    "case3": "output/case3/visualization/dns_timeline.png",
}

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

# Use tshark directly to avoid pyshark's display_filter parsing issues with LDAP packets
# Extract DNS queries via tshark CLI
print(f"[INFO] Extracting DNS queries from {PCAP_PATHS[CASE]} via tshark...")
cmd = [
    "tshark", "-r", PCAP_PATHS[CASE],
    "-Y", "dns",
    "--disable-protocol", "cldap",
    "--disable-protocol", "ldap",
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "dns.qry.name",
    "-E", "separator=|",
]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
if result.returncode != 0:
    # Fallback: try without DNS filter (capture all)
    print(f"[WARN] tshark with dns filter failed: {result.stderr[:200]}")
    sys.exit(1)

queries = []
for line in result.stdout.strip().split("\n"):
    if not line.strip():
        continue
    parts = line.split("|", 1)
    if len(parts) < 2 or not parts[1]:
        continue
    try:
        ts_epoch = float(parts[0])
        from datetime import datetime
        ts = datetime.fromtimestamp(ts_epoch)
    except ValueError:
        continue
    domain = parts[1].strip()
    if not domain or domain == "":
        continue
    parts_d = domain.rstrip(".").split(".")
    sld = parts_d[-2] if len(parts_d) >= 2 else domain
    entropy = shannon_entropy(sld)
    queries.append((ts, domain, entropy))

if not queries:
    print(f"[WARN] No DNS queries for {CASE}")
    sys.exit(0)

# Classify high entropy (potential DGA) threshold: > 3.5 bits/char
HIGH_ENTROPY_THRESHOLD = 3.5

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 9), dpi=110, gridspec_kw={"height_ratios": [3, 1]})

# Top: scatter of DNS queries (y=entropy, x=time, color by high entropy)
times = [q[0] for q in queries]
entropies = [q[2] for q in queries]
colors = ["#c43232" if e > HIGH_ENTROPY_THRESHOLD else "#1d5d8f" for e in entropies]
sizes = [40 if e > HIGH_ENTROPY_THRESHOLD else 12 for e in entropies]
ax1.scatter(times, entropies, c=colors, s=sizes, alpha=0.7, edgecolors="white", linewidth=0.3)
ax1.axhline(HIGH_ENTROPY_THRESHOLD, color="#c57c1f", linestyle="--", linewidth=1, alpha=0.7,
            label=f"DGA threshold ({HIGH_ENTROPY_THRESHOLD} bits/char)")
ax1.set_ylabel("Shannon entropy of SLD (bits/char)", fontsize=11)
ax1.set_title(
    f"DNS Query Timeline + DGA Detection — {CASE.upper()}\n"
    f"(Red = high-entropy potential DGA | Blue = normal)",
    fontsize=13, fontweight="bold", pad=10
)
ax1.grid(True, alpha=0.3, linestyle="--")
ax1.legend(loc="upper right", fontsize=10)
from matplotlib.dates import DateFormatter
ax1.xaxis.set_major_formatter(DateFormatter("%H:%M"))
plt.setp(ax1.xaxis.get_majorticklabels(), rotation=30, ha="right")

# Bottom: bar chart of top queried domains
domain_counts = Counter([q[1] for q in queries])
top_15 = domain_counts.most_common(15)
ax2.barh([d for d, _ in top_15][::-1], [c for _, c in top_15][::-1], color="#1d5d8f", alpha=0.8)
ax2.set_xlabel("Query count", fontsize=10)
ax2.set_title(f"Top 15 Queried Domains", fontsize=11, fontweight="bold")
ax2.grid(True, alpha=0.3, axis="x", linestyle="--")
ax2.tick_params(axis="y", labelsize=8)

plt.tight_layout()
plt.savefig(OUTPUT[CASE], bbox_inches="tight", dpi=110)
plt.close()

high_entropy_count = sum(1 for e in entropies if e > HIGH_ENTROPY_THRESHOLD)
print(f"[OK] Saved {OUTPUT[CASE]} — {len(queries)} queries, {high_entropy_count} high-entropy (potential DGA)")
