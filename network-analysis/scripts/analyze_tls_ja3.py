"""TLS/JA3 fingerprint analysis using tshark JSON output.
Disable CLDAP/LDAP dissectors to avoid tshark crash.
"""
import subprocess
import json
import csv
import hashlib
import os
import sys
from collections import defaultdict
from datetime import datetime

CASES = ["case1", "case2", "case3"]
PCAP_PATHS = {
    "case1": "pcap/2024-09-04-traffic-analysis-exercise.pcap",
    "case2": "pcap/2024-11-26-traffic-analysis-exercise.pcap",
    "case3": "pcap/2025-06-13-traffic-analysis-exercise.pcap",
}
OUTPUT_CSV = {c: f"output/{c}/visualization/tls_ja3.csv" for c in CASES}
OUTPUT_SUMMARY = {c: f"output/{c}/visualization/tls_ja3_summary.json" for c in CASES}
CROSS_CASE = "output/tls_ja3_cross_case.json"

GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}


def parse_int(s):
    """Parse hex or decimal string to int."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def compute_ja3(tls_version_int, cipher_suites, extensions, elliptic_curves, ec_point_formats):
    """Compute JA3 hash from parsed fields.
    JA3 = TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    def fmt(values):
        if not values:
            return ""
        return "-".join(str(v) for v in values)

    cs_clean = [c for c in cipher_suites if c not in GREASE]
    ext_clean = [e for e in extensions if e not in GREASE]
    ec_clean = [c for c in elliptic_curves if c not in GREASE]
    pf_clean = [p for p in ec_point_formats if p not in GREASE]

    raw = f"{tls_version_int},{fmt(cs_clean)},{fmt(ext_clean)},{fmt(ec_clean)},{fmt(pf_clean)}"
    return hashlib.md5(raw.encode()).hexdigest(), raw


def extract_tls_json(case):
    """Use tshark with -T json to parse TLS Client Hello."""
    print(f"[INFO] Extracting TLS Client Hello from {PCAP_PATHS[case]}...")
    cmd = [
        "tshark", "-r", PCAP_PATHS[case],
        "-Y", "tls.handshake.type == 1",
        "--disable-protocol", "cldap",
        "--disable-protocol", "ldap",
        "-T", "json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"[WARN] tshark returned {result.returncode}, stderr: {result.stderr[:200]}")
        return []

    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON decode error: {e}")
        return []

    rows = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})

        # Frame info
        frame = layers.get("frame", {})
        frame_no = frame.get("frame.number", "?")
        time_epoch = frame.get("frame.time_epoch", "0")
        try:
            time_f = float(time_epoch)
        except ValueError:
            time_f = 0.0

        # IP
        ip_layer = layers.get("ip", {})
        src_ip = ip_layer.get("ip.src", "")
        dst_ip = ip_layer.get("ip.dst", "")

        # TLS Handshake - nested under tls.record
        tls_layer = layers.get("tls", {})
        record = tls_layer.get("tls.record", {})
        hs = record.get("tls.handshake", {})
        if not hs:
            continue

        # Try to use pre-computed JA3 from tshark if available
        precomputed_ja3 = hs.get("tls.handshake.ja3", "")

        ver_str = hs.get("tls.handshake.version", "0x0303")
        try:
            ver_int = parse_int(ver_str)
        except ValueError:
            ver_int = 0x0303

        # Cipher suites - may be list
        cs_field = hs.get("tls.handshake.ciphersuites", {})
        cs_list = cs_field.get("tls.handshake.ciphersuite", [])
        if isinstance(cs_list, str):
            cs_list = [cs_list]
        cipher_suites = []
        for cs in cs_list:
            try:
                cipher_suites.append(parse_int(cs))
            except ValueError:
                continue

        # Extensions
        ext_field = hs.get("tls.handshake.extension", {})
        ext_list = ext_field.get("tls.handshake.extension.type", [])
        if isinstance(ext_list, str):
            ext_list = [ext_list]
        extensions = []
        for e in ext_list:
            try:
                extensions.append(parse_int(e))
            except ValueError:
                continue

        # Elliptic curves (supported_groups)
        ec_field = hs.get("tls.handshake.extensions_supported_group", {})
        ec_list = ec_field.get("tls.handshake.extensions_supported_group", [])
        if isinstance(ec_list, str):
            ec_list = [ec_list]
        elliptic_curves = []
        for ec in ec_list:
            try:
                elliptic_curves.append(parse_int(ec))
            except ValueError:
                continue

        # EC point formats
        pf_field = hs.get("tls.handshake.extensions_ec_point_format", {})
        pf_list = pf_field.get("tls.handshake.extension.ec_point_format", [])
        if isinstance(pf_list, str):
            pf_list = [pf_list]
        ec_pf = []
        for pf in pf_list:
            try:
                ec_pf.append(parse_int(pf))
            except ValueError:
                continue

        ja3_hash, ja3_raw = compute_ja3(ver_int, cipher_suites, extensions, elliptic_curves, ec_pf)

        # If we have precomputed JA3 from tshark, use it (more accurate)
        if precomputed_ja3 and precomputed_ja3.strip():
            ja3_hash = precomputed_ja3.strip()

        rows.append({
            "frame_no": frame_no,
            "timestamp": time_f,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "tls_version": ver_str,
            "tls_version_int": ver_int,
            "cipher_suites_count": len(cipher_suites),
            "extensions_count": len(extensions),
            "ec_groups_count": len(elliptic_curves),
            "ec_pf_count": len(ec_pf),
            "ja3_hash": ja3_hash,
            "ja3_raw": ja3_raw,
        })
    return rows


def analyze_case(case):
    rows = extract_tls_json(case)
    if not rows:
        print(f"[WARN] No TLS Client Hello extracted for {case}")
        return None

    csv_path = OUTPUT_CSV[case]
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    by_ja3 = defaultdict(list)
    for r in rows:
        by_ja3[r["ja3_hash"]].append(r)

    summary = {
        "case": case,
        "pcap": PCAP_PATHS[case],
        "total_tls_client_hello": len(rows),
        "unique_ja3": len(by_ja3),
        "top_10_ja3": [
            {
                "ja3_hash": h,
                "count": len(rs),
                "sample_src_ips": list(set(r["src_ip"] for r in rs))[:5],
                "sample_dst_ips": list(set(r["dst_ip"] for r in rs))[:5],
            }
            for h, rs in sorted(by_ja3.items(), key=lambda x: -len(x[1]))[:10]
        ],
    }
    with open(OUTPUT_SUMMARY[case], "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[OK] {case}: {len(rows)} TLS Client Hello, {len(by_ja3)} unique JA3")
    return by_ja3, rows


def build_cross_case(all_data):
    cross = {
        "generated_at": datetime.now().isoformat() + "Z",
        "cases": list(CASES),
        "ja3_per_case": {},
    }
    for case, data in all_data.items():
        by_ja3, _ = data
        cross["ja3_per_case"][case] = {
            "unique_ja3_count": len(by_ja3),
            "ja3_hashes": sorted(by_ja3.keys()),
        }

    all_sets = [set(cross["ja3_per_case"][c]["ja3_hashes"]) for c in CASES]
    cross["shared_all_3_cases"] = sorted(list(all_sets[0] & all_sets[1] & all_sets[2]))
    cross["shared_case1_case2"] = sorted(list(all_sets[0] & all_sets[1] - all_sets[2]))
    cross["shared_case1_case3"] = sorted(list(all_sets[0] & all_sets[2] - all_sets[1]))
    cross["shared_case2_case3"] = sorted(list(all_sets[1] & all_sets[2] - all_sets[0]))

    for i, case in enumerate(CASES):
        others = set()
        for j, other in enumerate(CASES):
            if i != j:
                others |= all_sets[j]
        unique = all_sets[i] - others
        cross["ja3_per_case"][case]["unique_to_case_count"] = len(unique)
        cross["ja3_per_case"][case]["unique_to_case_sample"] = sorted(list(unique))[:5]

    with open(CROSS_CASE, "w") as f:
        json.dump(cross, f, indent=2)
    print(f"\n[OK] Cross-case saved: {CROSS_CASE}")
    print(f"     Shared all 3: {len(cross['shared_all_3_cases'])}")
    for case in CASES:
        u = cross["ja3_per_case"][case]["unique_to_case_count"]
        print(f"     {case} unique: {u}")


if __name__ == "__main__":
    all_data = {}
    for case in CASES:
        result = analyze_case(case)
        if result:
            all_data[case] = result
    if all_data:
        build_cross_case(all_data)
    else:
        print("[WARN] No data extracted from any case")
