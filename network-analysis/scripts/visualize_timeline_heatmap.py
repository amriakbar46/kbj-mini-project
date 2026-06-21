import pyshark
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import sys
from datetime import datetime
from collections import defaultdict

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

PCAP_PATHS = {
    "case1": "pcap/2024-09-04-traffic-analysis-exercise.pcap",
    "case2": "pcap/2024-11-26-traffic-analysis-exercise.pcap",
    "case3": "pcap/2025-06-13-traffic-analysis-exercise.pcap",
}

OUTPUT = {
    "case1": "output/case1/visualization/timeline_heatmap.png",
    "case2": "output/case2/visualization/timeline_heatmap.png",
    "case3": "output/case3/visualization/timeline_heatmap.png",
}

# Track (minute_bin, host) -> count
activity = defaultdict(lambda: defaultdict(int))
all_minutes = set()
all_hosts = set()

cap = pyshark.FileCapture(PCAP_PATHS[CASE], keep_packets=False, display_filter="ip")
for pkt in cap:
    try:
        if hasattr(pkt, "ip") and hasattr(pkt, "sniff_time"):
            ts = pkt.sniff_time
            minute_bin = ts.replace(second=0, microsecond=0)
            src = pkt.ip.src
            dst = pkt.ip.dst
            all_minutes.add(minute_bin)
            all_hosts.add(src)
            all_hosts.add(dst)
            activity[minute_bin][src] += 1
            activity[minute_bin][dst] += 1
    except Exception:
        continue
cap.close()

if not all_minutes:
    print(f"[WARN] No data for {CASE}")
    sys.exit(0)

sorted_minutes = sorted(all_minutes)
# Limit to top 15 hosts by total activity
host_totals = defaultdict(int)
for m, hosts in activity.items():
    for h, c in hosts.items():
        host_totals[h] += c
top_hosts = sorted(host_totals.items(), key=lambda x: x[1], reverse=True)[:15]
top_host_names = [h for h, _ in top_hosts]

# Build matrix
matrix = np.zeros((len(top_host_names), len(sorted_minutes)))
host_idx = {h: i for i, h in enumerate(top_host_names)}
min_idx = {m: i for i, m in enumerate(sorted_minutes)}

for m, hosts in activity.items():
    for h, c in hosts.items():
        if h in host_idx:
            matrix[host_idx[h]][min_idx[m]] = c

fig, ax = plt.subplots(figsize=(16, 7), dpi=110)
im = ax.imshow(matrix, aspect="auto", cmap="YlOrRd", interpolation="nearest")
ax.set_yticks(range(len(top_host_names)))
ax.set_yticklabels(top_host_names, fontsize=9)
ax.set_xticks(range(0, len(sorted_minutes), max(1, len(sorted_minutes) // 12)))
ax.set_xticklabels(
    [sorted_minutes[i].strftime("%H:%M") for i in range(0, len(sorted_minutes), max(1, len(sorted_minutes) // 12))],
    rotation=45, ha="right", fontsize=9
)
ax.set_xlabel("Time (minute bin)", fontsize=11)
ax.set_ylabel("Top 15 hosts (by total packets)", fontsize=11)
ax.set_title(f"Timeline Activity Heatmap — {CASE.upper()}\n(PCAP: {PCAP_PATHS[CASE].split('/')[-1]})",
             fontsize=13, fontweight="bold", pad=10)
cbar = plt.colorbar(im, ax=ax, fraction=0.025)
cbar.set_label("Packets per minute", fontsize=10)
plt.tight_layout()
plt.savefig(OUTPUT[CASE], bbox_inches="tight", dpi=110)
plt.close()
print(f"[OK] Saved {OUTPUT[CASE]} — {len(top_host_names)} hosts × {len(sorted_minutes)} minutes")
