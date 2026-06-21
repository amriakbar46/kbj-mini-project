import pyshark
from collections import Counter
import sys, os

pcap_file = sys.argv[1]
case_name = os.path.basename(pcap_file)

print("=" * 70)
print(f"Analyzing: {case_name}")
print(f"Path: {pcap_file}")

cap = pyshark.FileCapture(pcap_file, keep_packets=False)

protocols = Counter()
src_ips = Counter()
dst_ips = Counter()
dns_packets = 0
http_packets = 0
tls_packets = 0
tcp_packets = 0
udp_packets = 0
packet_count = 0

for pkt in cap:
    packet_count += 1

    try:
        protocols[pkt.highest_layer] += 1
    except Exception:
        pass

    try:
        src_ips[pkt.ip.src] += 1
        dst_ips[pkt.ip.dst] += 1
    except Exception:
        pass

    if "DNS" in pkt:
        dns_packets += 1
    if "HTTP" in pkt:
        http_packets += 1
    if "TLS" in pkt:
        tls_packets += 1
    if "TCP" in pkt:
        tcp_packets += 1
    if "UDP" in pkt:
        udp_packets += 1

cap.close()

print(f"\nTotal packets: {packet_count}")

print("\nTop Protocols:")
for proto, count in protocols.most_common(10):
    print(f"{proto}: {count}")

print("\nTop Source IPs:")
for ip, count in src_ips.most_common(10):
    print(f"{ip}: {count}")

print("\nTop Destination IPs:")
for ip, count in dst_ips.most_common(10):
    print(f"{ip}: {count}")

print("\nProtocol Counters:")
print(f"TCP packets: {tcp_packets}")
print(f"UDP packets: {udp_packets}")
print(f"DNS packets: {dns_packets}")
print(f"HTTP packets: {http_packets}")
print(f"TLS packets: {tls_packets}")
