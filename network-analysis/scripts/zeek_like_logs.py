import os
import pyshark
import pandas as pd

#case 1
#PCAP_FILE = "pcap/2024-09-04-traffic-analysis-exercise.pcap"
#OUTPUT_DIR = "output/week2/zeek_like"

#case 2
#PCAP_FILE = "pcap/2024-11-26-traffic-analysis-exercise.pcap"
#OUTPUT_DIR = "output/case2/zeek_like"

#case 3
PCAP_FILE = "pcap/2025-06-13-traffic-analysis-exercise.pcap"
OUTPUT_DIR = "output/case3/zeek_like"

os.makedirs(OUTPUT_DIR, exist_ok=True)

capture = pyshark.FileCapture(PCAP_FILE)

conn_rows = []
http_rows = []
dns_rows = []

seen_conn = set()

for pkt in capture:

    try:
        # =========================
        # CONNECTION SUMMARY
        # =========================
        if hasattr(pkt, "ip") and hasattr(pkt, "tcp"):

            key = (
                pkt.ip.src,
                pkt.ip.dst,
                pkt.tcp.srcport,
                pkt.tcp.dstport
            )

            if key not in seen_conn:

                seen_conn.add(key)

                conn_rows.append({
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "src_port": pkt.tcp.srcport,
                    "dst_port": pkt.tcp.dstport,
                    "protocol": "TCP"
                })

        # =========================
        # HTTP LOG
        # =========================
        if hasattr(pkt, "http"):

            method = getattr(pkt.http, "request_method", "")
            host = getattr(pkt.http, "host", "")
            uri = getattr(pkt.http, "request_uri", "")
            ua = getattr(pkt.http, "user_agent", "")

            http_rows.append({
                "timestamp": pkt.sniff_time,
                "src_ip": pkt.ip.src,
                "dst_ip": pkt.ip.dst,
                "method": method,
                "host": host,
                "uri": uri,
                "user_agent": ua
            })

        # =========================
        # DNS LOG
        # =========================
        if hasattr(pkt, "dns"):

            query = getattr(pkt.dns, "qry_name", "")

            dns_rows.append({
                "timestamp": pkt.sniff_time,
                "src_ip": pkt.ip.src,
                "dst_ip": pkt.ip.dst,
                "query": query
            })

    except:
        pass

# SAVE CSV
conn_df = pd.DataFrame(conn_rows)
http_df = pd.DataFrame(http_rows)
dns_df = pd.DataFrame(dns_rows)

conn_df.to_csv(f"{OUTPUT_DIR}/conn_summary.csv", index=False)
http_df.to_csv(f"{OUTPUT_DIR}/http_summary.csv", index=False)
dns_df.to_csv(f"{OUTPUT_DIR}/dns_summary.csv", index=False)

# suspicious HTTP only
suspicious = http_df[
    http_df["uri"].astype(str).str.contains("foots.php", na=False)
]

suspicious.to_csv(
    f"{OUTPUT_DIR}/suspicious_http.csv",
    index=False
)

print("Saved:")
print(" - conn_summary.csv")
print(" - http_summary.csv")
print(" - dns_summary.csv")
print(" - suspicious_http.csv")
