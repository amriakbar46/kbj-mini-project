#!/usr/bin/env python3
"""
case3_payload_analyzer.py — Analyze 968 KB obfuscated payload from stream 90
Usage: python3 case3_payload_analyzer.py <path-to-payload.bin>

Performs:
  - Hash computation (MD5, SHA256)
  - Format detection (gzip/zlib/PE/HTML/PS1/etc)
  - Entropy analysis
  - String pattern matching (PowerShell cmdlets, base64, URLs, paths)
  - Variable name extraction
  - Decode base64 strings to readable text
  - Identify obfuscation patterns (string concat, char arrays, etc)
  - Report suspicious patterns

Reference: Case 3 (2025-06-13) — payload 968 KB analysis
Author: re-analysis 2026-06-21
"""

import re
import sys
import math
import hashlib
import base64
import zlib
from collections import Counter


SUSPICIOUS_PATTERNS = [
    (r'New-Object\s+Net\.WebClient', 'WebClient creation'),
    (r'WebClient\(\)', 'WebClient instantiation'),
    (r'Invoke-Expression', 'Invoke-Expression call'),
    (r'\$\(.*?\)\s*\|\s*iex', 'Expression piped to iex'),
    (r'powershell\.exe', 'powershell.exe reference'),
    (r'-enc(?:odedCommand)?\s+[A-Za-z0-9+/=]+', 'Encoded command'),
    (r'cmd\.exe\s*/c', 'cmd.exe /c'),
    (r'RegistryKey', '.NET Registry access'),
    (r'wmiprvse|winmgmt', 'WMI access'),
    (r'netsh\s+advfirewall', 'Firewall rule change'),
    (r'New-NetFirewallRule', 'PS firewall rule'),
    (r'DisableRealtimeMonitoring', 'Defender disable'),
    (r'Set-MpPreference|Add-MpPreference', 'Defender bypass'),
    (r'oauth2\.googleapis\.com', 'Google OAuth endpoint'),
    (r'aadcdn\.msftauth\.net', 'Microsoft auth endpoint'),
    (r'nodejs\.org', 'Node.js download'),
    (r'windows\.php\.net', 'PHP download'),
    (r'windows-msgas\.com|event-datamicrosoft\.live|trycloudflare\.com', 'C2 domain'),
]


def compute_hashes(data: bytes) -> dict:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
    }


def detect_format(data: bytes) -> dict:
    """Detect file format based on magic bytes and entropy."""
    format_info = {}
    format_info['first_4_bytes_hex'] = data[:4].hex()
    format_info['last_4_bytes_hex'] = data[-4:].hex() if len(data) >= 4 else 'N/A'
    format_info['first_4_bytes_ascii'] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:4])

    format_info['is_gzip'] = data[:2] == b'\x1f\x8b'
    format_info['is_zlib'] = data[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01')
    format_info['is_zip'] = data[:2] == b'PK'
    format_info['is_pe'] = data[:2] == b'MZ'
    format_info['is_html'] = b'<!DOCTYPE' in data[:1000] or b'<html' in data[:1000]
    format_info['is_xml'] = data[:5] == b'<?xml'
    format_info['is_powershell_scriptblock'] = data[:2] == b'${'  # PS variable expansion

    # Try gunzip
    if not format_info['is_gzip']:
        for i in range(20):
            if i + 2 > len(data):
                break
            try:
                zlib.decompress(data[i:i+1000], 31)
                format_info['gunzip_at_offset'] = i
                break
            except Exception:
                pass
    return format_info


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counter.values() if c > 0)


def find_patterns(data: bytes) -> dict:
    """Count occurrences of suspicious patterns."""
    text = data.decode('utf-8', errors='replace')
    results = {}
    for pat, desc in SUSPICIOUS_PATTERNS:
        matches = re.findall(pat, text, re.IGNORECASE)
        if matches:
            results[desc] = (len(matches), matches[:3])
    return results


def find_long_strings(data: bytes, min_len: int = 30, limit: int = 20) -> list:
    """Find longest ASCII sequences."""
    sequences = re.findall(rb'[\x20-\x7e]{%d,500}' % min_len, data)
    decoded = sorted(
        set(s.decode('ascii', errors='replace') for s in sequences),
        key=len, reverse=True
    )
    return decoded[:limit]


def decode_base64_strings(data: bytes, limit: int = 15) -> list:
    """Find and decode base64 strings that result in readable text."""
    text = data.decode('utf-8', errors='replace')
    b64_pattern = re.compile(r'"([A-Za-z0-9+/=]{20,500})"')
    matches = list(set(b64_pattern.findall(text)))

    decoded_results = []
    for s in matches:
        for pad in ['', '=', '==', '===']:
            try:
                decoded = base64.b64decode(s + pad)
                if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:20]):
                    text_decoded = decoded.decode('ascii', errors='replace')
                    if len(text_decoded) > 10:
                        # Check for interesting content
                        if any(kw in text_decoded for kw in [
                            'Invoke', 'http', 'Token', 'path', 'Web', 'IEX', 'IWR',
                            'System', 'oauth', 'php', 'Window', 'msftauth',
                            'trycloud', 'msgas', 'event-', 'powershell',
                        ]):
                            decoded_results.append((s, text_decoded))
                            break
            except Exception:
                pass
            if len(decoded_results) >= limit:
                break
    return decoded_results[:limit]


def extract_variable_names(data: bytes, limit: int = 30) -> list:
    """Extract PowerShell variable names."""
    text = data.decode('utf-8', errors='replace')
    var_pattern = re.compile(r'\$\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*=')
    return sorted(set(m for m in var_pattern.findall(text)))[:limit]


def find_urls(data: bytes, limit: int = 20) -> list:
    """Find URLs in payload."""
    text = data.decode('utf-8', errors='replace')
    urls = re.findall(r'https?://[a-zA-Z0-9./\-]+', text)
    return sorted(set(urls))[:limit]


def find_file_paths(data: bytes, limit: int = 20) -> list:
    """Find Windows file paths."""
    text = data.decode('utf-8', errors='replace')
    paths = re.findall(r'[A-Z]:\\\\[A-Za-z0-9_.\\\\-]+', text)
    return sorted(set(paths))[:limit]


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-payload.bin>")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    print("=" * 60)
    print("PAYLOAD ANALYSIS")
    print("=" * 60)

    # Hashes
    hashes = compute_hashes(data)
    print(f"MD5    : {hashes['md5']}")
    print(f"SHA256 : {hashes['sha256']}")
    print(f"Size   : {hashes['size']:,} bytes")

    # Format detection
    print("\n" + "=" * 60)
    print("FORMAT DETECTION")
    print("=" * 60)
    fmt = detect_format(data)
    for k, v in fmt.items():
        print(f"  {k:30}: {v}")

    # Entropy
    print("\n" + "=" * 60)
    print("ENTROPY ANALYSIS")
    print("=" * 60)
    entropy = compute_entropy(data)
    classification = ('HIGH (encrypted/compressed)' if entropy > 7
                      else 'mixed (compressed/code)' if entropy > 6
                      else 'structured text (source code)')
    print(f"  Full file entropy: {entropy:.3f} bits/byte")
    print(f"  Classification: {classification}")
    print(f"  Printable ASCII: {sum(1 for b in data if 32 <= b < 127) / len(data) * 100:.1f}%")
    print(f"  Whitespace: {sum(1 for b in data if b in (9, 10, 13, 32)) / len(data) * 100:.1f}%")

    # Suspicious patterns
    print("\n" + "=" * 60)
    print("SUSPICIOUS PATTERNS")
    print("=" * 60)
    patterns = find_patterns(data)
    if patterns:
        for desc, (count, samples) in sorted(patterns.items(), key=lambda x: -x[1][0]):
            print(f"  {desc:40}: {count:5} occurrences")
            for s in samples[:2]:
                print(f"    - {str(s)[:120]}")
    else:
        print("  (none found)")

    # Long strings
    print("\n" + "=" * 60)
    print("LONGEST ASCII SEQUENCES (top 15)")
    print("=" * 60)
    long_strings = find_long_strings(data, limit=15)
    for s in long_strings:
        if len(s) <= 250 and any(c.isalpha() for c in s):
            print(f"  [{len(s):4}] {s[:200]}")

    # Base64 decode
    print("\n" + "=" * 60)
    print("BASE64 STRINGS (decoded, suspicious content)")
    print("=" * 60)
    b64_decoded = decode_base64_strings(data, limit=10)
    for s, d in b64_decoded:
        print(f"  Encoded: {s[:60]}{'...' if len(s) > 60 else ''}")
        print(f"  Decoded: {d[:150]}")
        print()

    # Variable names
    print("\n" + "=" * 60)
    print("VARIABLE NAMES (top 20)")
    print("=" * 60)
    variables = extract_variable_names(data, limit=20)
    for v in variables:
        print(f"  ${v}")

    # URLs
    print("\n" + "=" * 60)
    print("URLS / DOMAINS")
    print("=" * 60)
    urls = find_urls(data)
    for u in urls:
        print(f"  {u}")

    # File paths
    print("\n" + "=" * 60)
    print("FILE PATHS")
    print("=" * 60)
    paths = find_file_paths(data)
    for p in paths:
        print(f"  {p}")


if __name__ == "__main__":
    main()
