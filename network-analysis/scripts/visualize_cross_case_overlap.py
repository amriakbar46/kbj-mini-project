import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib_venn import venn3
import sys

def load_iocs(case):
    """Return set of IPs and domains from IOC CSV."""
    path = f"output/{case}/ioc/ioc_{case}.csv"
    ips = set()
    domains = set()
    try:
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["ioc_type"] == "ip":
                    ips.add(row["value"])
                elif row["ioc_type"] == "domain":
                    domains.add(row["value"])
    except FileNotFoundError:
        pass
    return ips, domains


cases = ["case1", "case2", "case3"]
case_labels = ["Case 1 (2024-09-04)", "Case 2 (2024-11-26)", "Case 3 (2025-06-13)"]

# Build IP sets (filter out private/RFC1918)
def is_public(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    o1, o2 = int(parts[0]), int(parts[1])
    if o1 == 10 or o1 == 127 or o1 == 0 or o1 >= 224:
        return False
    if o1 == 172 and 16 <= o2 <= 31:
        return False
    if o1 == 192 and o2 == 168:
        return False
    if o1 == 255:
        return False
    return True

ips = {c: set() for c in cases}
domains = {c: set() for c in cases}
for c in cases:
    ip_set, dom_set = load_iocs(c)
    ips[c] = {ip for ip in ip_set if is_public(ip)}
    domains[c] = dom_set

# Print stats
print("=== IP sets (public only) ===")
for c, s in ips.items():
    print(f"  {c}: {len(s)} public IPs")
print("=== Domain sets ===")
for c, s in domains.items():
    print(f"  {c}: {len(s)} domains")

# Save master IOC CSV
MASTER = "output/master_ioc.csv"
with open(MASTER, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["case", "ioc_type", "value", "shared_with"])
    # IPs
    all_ips = set()
    for c in cases:
        for ip in sorted(ips[c]):
            shared = [other for other in cases if other != c and ip in ips[other]]
            all_ips.add(ip)
            writer.writerow([c, "ip", ip, ",".join(shared) if shared else "unique"])
    # Domains
    all_domains = set()
    for c in cases:
        for dom in sorted(domains[c]):
            shared = [other for other in cases if other != c and dom in domains[other]]
            all_domains.add(dom)
            writer.writerow([c, "domain", dom, ",".join(shared) if shared else "unique"])

print(f"[OK] Master IOC saved: {MASTER} — {len(all_ips)} unique IPs, {len(all_domains)} unique domains")

# Build Venn diagrams (IPs + Domains)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), dpi=110)

plt.sca(ax1)
v1 = venn3(
    [ips[c] for c in cases],
    set_labels=case_labels,
    set_colors=("#c43232", "#c57c1f", "#1f7a4d"),
    alpha=0.55,
)
plt.title("Public IP Overlap Across 3 Cases", fontsize=13, fontweight="bold", pad=12)

plt.sca(ax2)
v2 = venn3(
    [domains[c] for c in cases],
    set_labels=case_labels,
    set_colors=("#c43232", "#c57c1f", "#1f7a4d"),
    alpha=0.55,
)
plt.title("Domain Overlap Across 3 Cases", fontsize=13, fontweight="bold", pad=12)

fig.suptitle(
    "Cross-Case Infrastructure Overlap — Venn Diagram",
    fontsize=14, fontweight="bold", y=1.02
)
plt.tight_layout()
plt.savefig("output/visualization/cross_case_overlap.png", bbox_inches="tight", dpi=110)
plt.close()
print(f"[OK] Saved output/visualization/cross_case_overlap.png")

# Also write a summary CSV with overlap stats
OVERLAP = "output/cross_case_overlap_stats.csv"
with open(OVERLAP, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["metric", "case1_case2", "case1_case3", "case2_case3", "all_three"])
    ip_overlaps = {}
    for pair in [("case1", "case2"), ("case1", "case3"), ("case2", "case3")]:
        ip_overlaps["_".join(pair)] = len(ips[pair[0]] & ips[pair[1]])
    ip_overlaps["all_three"] = len(ips["case1"] & ips["case2"] & ips["case3"])
    writer.writerow(["shared_public_ips"] + [ip_overlaps["case1_case2"], ip_overlaps["case1_case3"],
                                              ip_overlaps["case2_case3"], ip_overlaps["all_three"]])
    dom_overlaps = {}
    for pair in [("case1", "case2"), ("case1", "case3"), ("case2", "case3")]:
        dom_overlaps["_".join(pair)] = len(domains[pair[0]] & domains[pair[1]])
    dom_overlaps["all_three"] = len(domains["case1"] & domains["case2"] & domains["case3"])
    writer.writerow(["shared_domains"] + [dom_overlaps["case1_case2"], dom_overlaps["case1_case3"],
                                            dom_overlaps["case2_case3"], dom_overlaps["all_three"]])
print(f"[OK] Overlap stats saved: {OVERLAP}")
