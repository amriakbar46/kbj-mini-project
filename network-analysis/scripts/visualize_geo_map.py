import requests
import folium
import sys
import csv
import time

CASE = sys.argv[1] if len(sys.argv) > 1 else "case1"

IOC_CSV = {
    "case1": "output/case1/ioc/ioc_case1.csv",
    "case2": "output/case2/ioc/ioc_case2.csv",
    "case3": "output/case3/ioc/ioc_case3.csv",
}

OUTPUT_HTML = {
    "case1": "output/case1/visualization/geo_map.html",
    "case2": "output/case2/visualization/geo_map.html",
    "case3": "output/case3/visualization/geo_map.html",
}

# C2 IPs per case (confirmed from incident reports)
C2_IPS = {
    "case1": {"79.124.78.197": "C2 (HTTP beacon)"},
    "case2": {"194.180.191.64": "C2 (NetSupport RAT)"},
    "case3": {
        "104.21.16.1": "C2 (Cloudflare resolved)",
        "104.21.24.186": "C2 (Cloudflare resolved)",
        "104.21.64.1": "C2 (Cloudflare resolved)",
        "104.21.80.1": "C2 (Cloudflare resolved)",
        "104.21.96.1": "C2 (Cloudflare resolved)",
        "104.21.112.1": "C2 (Cloudflare resolved)",
        "104.16.230.132": "C2 (Cloudflare resolved)",
        "104.16.231.132": "C2 (Cloudflare resolved)",
    },
}

VICTIM_IPS = {
    "case1": "172.17.0.99",
    "case2": "10.11.26.183",
    "case3": "10.6.13.133",
}


def lookup_ip(ip):
    """Lookup IP via ip-api.com. Returns dict or None."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,region,regionName,city,lat,lon,org,query"},
            timeout=10,
        )
        data = r.json()
        if data.get("status") == "success":
            return data
    except Exception as e:
        print(f"  [WARN] lookup {ip} failed: {e}")
    return None


# Read IPs from IOC CSV
all_ips = set()
with open(IOC_CSV[CASE]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["ioc_type"] == "ip":
            all_ips.add(row["value"])

print(f"[INFO] {CASE}: {len(all_ips)} unique IPs found in IOC CSV")

# Filter out private IPs (RFC 1918) and link-local
def is_public(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    o1 = int(parts[0])
    o2 = int(parts[1])
    if o1 == 10:
        return False
    if o1 == 172 and 16 <= o2 <= 31:
        return False
    if o1 == 192 and o2 == 168:
        return False
    if o1 == 127:
        return False
    if o1 == 0:
        return False
    if o1 >= 224:
        return False
    return True

public_ips = sorted([ip for ip in all_ips if is_public(ip)])
print(f"[INFO] {len(public_ips)} public IPs to geolocate")

# Lookup each
geo_data = []
for i, ip in enumerate(public_ips):
    data = lookup_ip(ip)
    if data:
        geo_data.append({"ip": ip, **data})
        print(f"  [{i+1}/{len(public_ips)}] {ip} -> {data.get('country')}, {data.get('city')}")
    time.sleep(1.4)  # ip-api.com free tier: 45 req/min = 1.33s/req

# Save geo data to CSV for reuse
GEO_CSV = f"output/{CASE}/visualization/geo_data.csv"
with open(GEO_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["ip", "country", "countryCode", "city", "lat", "lon", "org", "is_c2"])
    writer.writeheader()
    for r in geo_data:
        c2_ips = C2_IPS.get(CASE, {})
        writer.writerow({
            "ip": r["ip"],
            "country": r.get("country", ""),
            "countryCode": r.get("countryCode", ""),
            "city": r.get("city", ""),
            "lat": r.get("lat", 0),
            "lon": r.get("lon", 0),
            "org": r.get("org", ""),
            "is_c2": "yes" if r["ip"] in c2_ips else "no",
        })
print(f"[OK] Geo data saved: {GEO_CSV}")

# Build folium map
m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB positron")

# Plot all IPs
for r in geo_data:
    is_c2 = r["ip"] in C2_IPS.get(CASE, {})
    color = "red" if is_c2 else "blue"
    icon = "exclamation-triangle" if is_c2 else "circle"
    folium.Marker(
        location=[r["lat"], r["lon"]],
        popup=folium.Popup(
            f"<b>{r['ip']}</b><br>"
            f"{r.get('city', 'N/A')}, {r.get('country', 'N/A')}<br>"
            f"Org: {r.get('org', 'N/A')}<br>"
            f"{'C2 / Malicious' if is_c2 else 'Other (public)'}",
            max_width=300
        ),
        tooltip=f"{r['ip']} — {r.get('country', 'N/A')}",
        icon=folium.Icon(color=color, icon=icon, prefix="fa")
    ).add_to(m)

# Add legend
legend_html = f"""
<div style="position: fixed; bottom: 30px; left: 30px; z-index: 1000;
     background: white; padding: 10px 14px; border: 2px solid #444; border-radius: 8px;
     font-family: Arial; font-size: 12px;">
  <b>{CASE.upper()} — Geo Map</b><br>
  <i style="color:red;">●</i> C2 / Confirmed malicious ({len(C2_IPS.get(CASE, {}))})<br>
  <i style="color:blue;">●</i> Other public IP ({sum(1 for r in geo_data if r['ip'] not in C2_IPS.get(CASE, {}))})<br>
  Total geolocated: {len(geo_data)} / {len(public_ips)}
</div>
"""
m.get_root().html.add_child(folium.Element(legend_html))

m.save(OUTPUT_HTML[CASE])
print(f"[OK] Saved {OUTPUT_HTML[CASE]}")
