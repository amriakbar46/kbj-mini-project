import json
import csv
from collections import Counter
import pyshark

#case1
#PCAP = "pcap/2024-09-04-traffic-analysis-exercise.pcap"
#IOC_CSV = "output/case1/ioc/ioc_case1.csv"
#SUMMARY_JSON = "output/case1/ioc/summary_case1.json"

# case2
#PCAP = "pcap/2024-11-26-traffic-analysis-exercise.pcap"
#IOC_CSV = "output/case2/ioc/ioc_case2.csv"
#SUMMARY_JSON = "output/case2/ioc/summary_case2.json"

# case3
PCAP = "pcap/2025-06-13-traffic-analysis-exercise.pcap"
IOC_CSV = "output/case3/ioc/ioc_case3.csv"
SUMMARY_JSON = "output/case3/ioc/summary_case3.json"

unique_ips = set()
dns_queries = set()
http_requests = []
user_agents = set()
suspicious_posts = []

protocols = Counter()

cap = pyshark.FileCapture(
    PCAP,
    keep_packets=False,
    display_filter="ip or dns or http"
)

for pkt in cap:
    try:
        if hasattr(pkt, "highest_layer"):
            protocols[pkt.highest_layer] += 1

        if hasattr(pkt, "ip"):
            unique_ips.add(pkt.ip.src)
            unique_ips.add(pkt.ip.dst)

        if hasattr(pkt, "dns"):
            if hasattr(pkt.dns, "qry_name"):
                dns_queries.add(pkt.dns.qry_name)

        if hasattr(pkt, "http"):
            method = getattr(pkt.http, "request_method", "")
            host = getattr(pkt.http, "host", "")
            uri = getattr(pkt.http, "request_uri", "")
            ua = getattr(pkt.http, "user_agent", "")

            if ua:
                user_agents.add(ua)

            if method:
                item = {
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "user_agent": ua,
                    "src_ip": getattr(pkt.ip, "src", ""),
                    "dst_ip": getattr(pkt.ip, "dst", ""),
                    "time": str(pkt.sniff_time),
                }
                http_requests.append(item)

                if method == "POST" or "foots.php" in uri:
                    suspicious_posts.append(item)

    except Exception:
        continue

cap.close()

rows = []

for ip in sorted(unique_ips):
    rows.append(["ip", ip, "unique IP address"])

for domain in sorted(dns_queries):
    rows.append(["domain", domain, "DNS query"])

for req in http_requests:
    value = f'{req["method"]} http://{req["host"]}{req["uri"]}'
    note = f'src={req["src_ip"]}, dst={req["dst_ip"]}'
    rows.append(["url", value, note])

for ua in sorted(user_agents):
    rows.append(["user_agent", ua, "HTTP User-Agent"])

with open(IOC_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["ioc_type", "value", "notes"])
    writer.writerows(rows)

summary = {
    "pcap": PCAP,
    "unique_ip_count": len(unique_ips),
    "dns_query_count": len(dns_queries),
    "http_request_count": len(http_requests),
    "user_agent_count": len(user_agents),
    "suspicious_post_count": len(suspicious_posts),
    "protocol_counter": dict(protocols),
    "suspicious_posts": suspicious_posts,
}

with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))
