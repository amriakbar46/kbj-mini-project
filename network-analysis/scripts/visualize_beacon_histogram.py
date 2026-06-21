import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
import os

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

BEACON_CSV = {
    "case1": "output/case1/ioc/beacon_intervals.csv",
    "case2": "output/case2/ioc/beacon_intervals.csv",
    "case3": "output/case3/ioc/beacon_intervals.csv",
}

OUTPUT = {
    "case1": "output/case1/visualization/beacon_histogram.png",
    "case2": "output/case2/visualization/beacon_histogram.png",
    "case3": "output/case3/visualization/beacon_histogram.png",
}

if not os.path.exists(BEACON_CSV[CASE]):
    print(f"[WARN] No beacon CSV for {CASE}")
    sys.exit(0)

df = pd.read_csv(BEACON_CSV[CASE])
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.dropna(subset=["interval_seconds"])
df = df[df["interval_seconds"] < 1000]  # remove outliers (gaps)

# Group by destination (host)
hosts = df["dst_ip"].unique()

fig, axes = plt.subplots(
    len(hosts), 1,
    figsize=(13, max(3, 2.2 * len(hosts))),
    dpi=110,
)
if len(hosts) == 1:
    axes = [axes]

for ax, host in zip(axes, hosts):
    host_df = df[df["dst_ip"] == host]
    intervals = host_df["interval_seconds"]
    n = len(intervals)
    median = intervals.median()
    mean = intervals.mean()
    ax.hist(intervals, bins=30, color="#1d5d8f", edgecolor="white", alpha=0.85)
    ax.axvline(median, color="#c43232", linestyle="--", linewidth=2, label=f"Median = {median:.1f}s")
    ax.axvline(mean, color="#c57c1f", linestyle=":", linewidth=2, label=f"Mean = {mean:.1f}s")
    ax.set_title(f"Beacon intervals to {host} (n={n})", fontsize=11, fontweight="bold")
    ax.set_xlabel("Interval (seconds)", fontsize=10)
    ax.set_ylabel("Count", fontsize=10)
    ax.grid(True, alpha=0.3, linestyle="--")
    ax.legend(loc="upper right", fontsize=9)

fig.suptitle(
    f"Beaconing Detector — Interval Histogram per Host — {CASE.upper()}",
    fontsize=13, fontweight="bold", y=1.001
)
plt.tight_layout()
plt.savefig(OUTPUT[CASE], bbox_inches="tight", dpi=110)
plt.close()
print(f"[OK] Saved {OUTPUT[CASE]} — {len(hosts)} host(s), {len(df)} intervals")
