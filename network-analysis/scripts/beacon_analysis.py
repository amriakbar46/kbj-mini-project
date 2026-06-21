import pyshark
import pandas as pd
from datetime import datetime

#case 1
#PCAP_FILE = "pcap/2024-09-04-traffic-analysis-exercise.pcap"
#C2_IP = "79.124.78.197"
#OUTPUT_CSV = "output/case1/ioc/beacon_intervals.csv"

#case 2
#PCAP_FILE = "pcap/2024-11-26-traffic-analysis-exercise.pcap"
#C2_IP = "194.180.191.64"
#OUTPUT_CSV = "output/case2/ioc/beacon_intervals.csv"

#case 3
PCAP_FILE = "pcap/2025-06-13-traffic-analysis-exercise.pcap"
C2_IP = "104.21.16.1"
OUTPUT_CSV = "output/case3/ioc/beacon_intervals.csv"

capture = pyshark.FileCapture(
    PCAP_FILE,
    display_filter='http.request.method == "POST"'
)

rows = []

for pkt in capture:
    try:
        ts = pkt.sniff_time

        host = ""
        uri = ""

        if hasattr(pkt.http, 'host'):
            host = pkt.http.host

        if hasattr(pkt.http, 'request_uri'):
            uri = pkt.http.request_uri

        rows.append({
            "timestamp": ts,
            "src_ip": pkt.ip.src,
            "dst_ip": pkt.ip.dst,
            "host": host,
            "uri": uri
        })

    except:
        pass

df = pd.DataFrame(rows)

# filter suspected C2 only

#case 1
#df = df[df["dst_ip"] == "79.124.78.197"]

#case 2
df = df[df["dst_ip"] == C2_IP]

#case 3
df = df[
    (df["src_ip"] == "10.6.13.133") &
    (df["host"].isin([
        "windows-msgas.com",
        "event-datamicrosoft.live",
        "varying-rentals-calgary-predict.trycloudflare.com"
    ]))
]


df = df.sort_values("timestamp")

# interval calculation
df["interval_seconds"] = df["timestamp"].diff().dt.total_seconds()

print(df[[
    "timestamp",
    "src_ip",
    "dst_ip",
    "uri",
    "interval_seconds"
]])

#df.to_csv("output/beacon_intervals.csv", index=False)

df.to_csv(OUTPUT_CSV, index=False)
print(f"\nSaved to {OUTPUT_CSV}")

print("\nSaved to output/beacon_intervals.csv")
