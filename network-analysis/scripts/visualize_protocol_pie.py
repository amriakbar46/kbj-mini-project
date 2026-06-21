import pyshark
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import json
import sys

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

PCAP_PATHS = {
    "case1": "pcap/2024-09-04-traffic-analysis-exercise.pcap",
    "case2": "pcap/2024-11-26-traffic-analysis-exercise.pcap",
    "case3": "pcap/2025-06-13-traffic-analysis-exercise.pcap",
}

OUTPUT = {
    "case1": "output/case1/visualization/protocol_pie.png",
    "case2": "output/case2/visualization/protocol_pie.png",
    "case3": "output/case3/visualization/protocol_pie.png",
}

from collections import Counter
protocols = Counter()

cap = pyshark.FileCapture(PCAP_PATHS[CASE], keep_packets=False, display_filter="ip or arp")
for pkt in cap:
    try:
        if hasattr(pkt, "highest_layer"):
            layer = pkt.highest_layer
            if layer and layer != "ARP":
                protocols[layer] += 1
    except Exception:
        continue
cap.close()

# Top 8 + others
top = protocols.most_common(8)
labels = [x[0] for x in top]
sizes = [x[1] for x in top]
others_count = sum(c for _, c in protocols.most_common()[8:])
if others_count > 0:
    labels.append("Others")
    sizes.append(others_count)

fig, ax = plt.subplots(figsize=(9, 7), dpi=110)
colors = plt.cm.tab20(range(len(labels)))
wedges, texts, autotexts = ax.pie(
    sizes, labels=None, autopct=lambda p: f"{p:.1f}%" if p > 2 else "",
    startangle=90, colors=colors, pctdistance=0.78,
    wedgeprops=dict(width=0.55, edgecolor="white", linewidth=1.5)
)
ax.legend(wedges, [f"{l} ({s:,})" for l, s in zip(labels, sizes)],
          title="Protocol (count)", loc="center left", bbox_to_anchor=(1.02, 0.5),
          fontsize=10, title_fontsize=11)
ax.set_title(f"Protocol Distribution — {CASE.upper()}\n(PCAP: {PCAP_PATHS[CASE].split('/')[-1]})",
             fontsize=13, fontweight="bold", pad=14)
plt.tight_layout()
plt.savefig(OUTPUT[CASE], bbox_inches="tight", dpi=110)
plt.close()
print(f"[OK] Saved {OUTPUT[CASE]} — {sum(sizes):,} packets across {len(labels)} protocols")
