import pandas as pd
import matplotlib.pyplot as plt

#case 1
#INPUT_FILE = "output/week2/zeek_like/suspicious_http.csv"
#OUTPUT_FILE = "output/week2/beacon_timeline.png"

#case 2
#INPUT_FILE = "output/case2/zeek_like/http_summary.csv"
#OUTPUT_FILE = "output/case2/visualization/beacon_timeline.png"

#case 3
INPUT_FILE = "output/case3/zeek_like/http_summary.csv"
OUTPUT_FILE = "output/case3/visualization/beacon_timeline.png"

df = pd.read_csv(INPUT_FILE)

# hanya POST dari victim ke C2
#case 1
#df = df[
#    (df["src_ip"] == "172.17.0.99") &
#    (df["dst_ip"] == "79.124.78.197") &
#    (df["method"] == "POST")
#]

#case 2
#df = df[
#    (df["src_ip"] == "10.11.26.183") &
#    (df["dst_ip"] == "194.180.191.64") &
#    (df["method"] == "POST")
#]

#case 3
C2_HOSTS = [
    "windows-msgas.com",
    "event-datamicrosoft.live",
    "eventdata-microsoft.live",
    "varying-rentals-calgary-predict.trycloudflare.com"
]

df = df[
    (df["src_ip"] == "10.6.13.133") &
    (df["method"] == "POST") &
    (df["host"].isin(C2_HOSTS))
]

df["timestamp"] = pd.to_datetime(df["timestamp"])

df = df.sort_values("timestamp")

# index request
df["request_number"] = range(1, len(df) + 1)

plt.figure(figsize=(12, 5))

plt.plot(
    df["timestamp"],
    df["request_number"],
    marker="o"
)

plt.title("Case 3 HTTP Beacon Timeline - PowerShell C2")
plt.xlabel("Timestamp")
plt.ylabel("Beacon Request Number")

plt.grid(True)

plt.tight_layout()

plt.savefig(OUTPUT_FILE)

print(f"saved: {OUTPUT_FILE}")
