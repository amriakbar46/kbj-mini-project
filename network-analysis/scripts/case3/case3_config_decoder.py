#!/usr/bin/env python3
"""
case3_config_decoder.py — Decode obfuscated config.cfg (PHP RAT)
Usage: python3 case3_config_decoder.py <path-to-config.cfg>

Performs:
  - Hex-escape string decoding (PHP \\x41 -> A, etc.)
  - Extract embedded C2 domains
  - Extract fallback IP addresses
  - Extract command code array ($D_3Y7)
  - Identify all function definitions
  - Extract XOR constants from path generation
  - Extract recon PowerShell commands
  - Extract persistence registry command
  - Identify Node.js cascade URL

Reference: Case 3 (2025-06-13) — BYOI PHP RAT config.cfg analysis
Author: re-analysis 2026-06-21
"""

import re
import sys
from collections import OrderedDict


def load_file(filepath: str) -> str:
    """Load file with UTF-8 BOM tolerance."""
    with open(filepath, 'rb') as f:
        data = f.read()
    return data.decode('utf-8-sig', errors='replace')


def decode_php_unicode_escape(data: str) -> str:
    """Decode PHP \\xHH and \\OOO (octal) unicode escape sequences in a string."""
    return bytes(data, 'utf-8').decode('unicode_escape', errors='replace')


def extract_ips(decoded: str) -> list:
    """Extract all IP addresses from decoded content."""
    return sorted(set(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decoded)))


def extract_domains(decoded: str) -> list:
    """Extract all domains (TLD .com/.live/.org/.net)."""
    domains = set(re.findall(r'[a-z0-9-]+\.(?:com|live|org|net)', decoded, re.I))
    return sorted(d for d in domains if not d.endswith('.local') and len(d) > 5)


def extract_functions(decoded: str) -> list:
    """Extract all PHP function names."""
    return sorted(set(re.findall(r'function ([A-Za-z0-9_]+)\s*\(', decoded)))


def extract_command_codes(data_raw: str) -> list:
    """Extract $D_3Y7 command code array from raw file (hex-escaped).

    Strategy: find the D_3Y7 = [ ... ] array and decode all string values
    in it. Also fallback to scanning all hex-escaped strings and filtering
    to known command code keywords.
    """
    known_codes = {'EXE', 'DLL', 'JS', 'CMD', 'ACTIVE', 'AUTORUN', 'OFF'}

    array_match = re.search(r'\$D_3Y7\s*=\s*\[([^\]]+)\]', data_raw, re.DOTALL)
    if array_match:
        array_content = array_match.group(1)
        hex_strings = re.findall(r'"((?:\\(?:x[0-9a-fA-F]{2}|[0-7]{1,3}))+)"', array_content)
        decoded_codes = []
        for s in hex_strings:
            try:
                decoded = bytes(s, 'ascii').decode('unicode_escape')
                if decoded in known_codes:
                    decoded_codes.append(decoded)
            except Exception:
                pass
        if decoded_codes:
            return decoded_codes

    hex_strings = re.findall(r'"((?:\\(?:x[0-9a-fA-F]{2}|[0-7]{1,3}))+)"', data_raw)
    decoded_codes = []
    seen = set()
    for s in hex_strings:
        try:
            decoded = bytes(s, 'ascii').decode('unicode_escape')
            if decoded in known_codes and decoded not in seen:
                seen.add(decoded)
                decoded_codes.append(decoded)
        except Exception:
            pass
    return decoded_codes


def extract_xor_constants(decoded: str) -> list:
    """Extract XOR constants from rxiXT() path generation function.

    Strategy: find the rxiXT function body, then look for XOR constants within it.
    """
    func_match = re.search(
        r'function\s+rxiXT\s*\([^)]*\)\s*\{(.*?)(?=function\s+[A-Za-z0-9_]+\s*\()',
        decoded, re.DOTALL
    )
    if func_match:
        func_body = func_match.group(1)
        xor_pattern = re.compile(r'\^\s*=\s*0x([0-9a-fA-F]{8})')
        constants = sorted(set(m.upper() for m in xor_pattern.findall(func_body)))
        if constants:
            return constants

    xor_pattern = re.compile(r'\^\s*=\s*0x([0-9a-fA-F]{8})')
    return sorted(set(m.upper() for m in xor_pattern.findall(decoded)))


def extract_recon_commands(decoded: str) -> list:
    """Extract PowerShell recon commands from mNFE9() function."""
    patterns = [
        r'systeminfo[^\s]*',
        r'Get-Service',
        r'Get-PSDrive',
        r'Get-NetNeighbor',
        r'arp -a',
        r'tasklist /svc',
        r'WindowsPrincipal',
    ]
    found = []
    for p in patterns:
        if re.search(p, decoded):
            found.append(p)
    return found


def extract_persistence_command(decoded: str) -> str:
    """Extract literal 'reg add' command from UrHlx() function."""
    m = re.search(r'reg add[^\"]{0,200}', decoded)
    return m.group(0) if m else None


def extract_nodejs_url(decoded: str) -> str:
    """Extract Node.js download URL from JS command (case 'JS=2')."""
    m = re.search(r'(https?://nodejs\.org/dist/v[0-9.]+/[a-z0-9.-]+\.zip)', decoded)
    return m.group(1) if m else None


def extract_run_key_target(decoded: str) -> str:
    """Extract the registry key path used for persistence."""
    m = re.search(r'(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)', decoded)
    return m.group(1) if m else None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-config.cfg>")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        raw = load_file(filepath)
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    print("=" * 60)
    print("CONFIG.CFG PHP RAT ANALYSIS")
    print("=" * 60)
    print(f"File: {filepath}")
    print(f"Size: {len(raw):,} chars")

    # Decode the file
    decoded = decode_php_unicode_escape(raw)

    # Section 1: IPs
    print("\n" + "=" * 60)
    print("IP ADDRESSES (decoded)")
    print("=" * 60)
    ips = extract_ips(decoded)
    for ip in ips:
        print(f"  {ip}")

    # Section 2: Domains
    print("\n" + "=" * 60)
    print("DOMAINS (decoded)")
    print("=" * 60)
    domains = extract_domains(decoded)
    for d in domains:
        print(f"  {d}")

    # Section 3: Functions
    print("\n" + "=" * 60)
    print("FUNCTION NAMES (decoded)")
    print("=" * 60)
    funcs = extract_functions(decoded)
    for f in funcs:
        print(f"  {f}")

    # Section 4: Command codes
    print("\n" + "=" * 60)
    print("COMMAND CODES (from $D_3Y7)")
    print("=" * 60)
    codes = extract_command_codes(raw)
    for c in codes:
        print(f"  {c}")

    # Section 5: XOR constants
    print("\n" + "=" * 60)
    print("XOR CONSTANTS (from rxiXT path generation)")
    print("=" * 60)
    xors = extract_xor_constants(decoded)
    for x in xors:
        print(f"  0x{x}")

    # Section 6: Recon commands
    print("\n" + "=" * 60)
    print("RECON COMMANDS (from mNFE9)")
    print("=" * 60)
    recon = extract_recon_commands(decoded)
    for r in recon:
        print(f"  {r}")

    # Section 7: Persistence
    print("\n" + "=" * 60)
    print("PERSISTENCE (from UrHlx)")
    print("=" * 60)
    run_key = extract_run_key_target(decoded)
    if run_key:
        print(f"  Registry: {run_key}")
    reg_cmd = extract_persistence_command(decoded)
    if reg_cmd:
        print(f"  Command: reg add ... {reg_cmd[8:100]}...")

    # Section 8: Node.js URL
    print("\n" + "=" * 60)
    print("NODE.JS CASCADE URL (from JS=2 command)")
    print("=" * 60)
    nodejs = extract_nodejs_url(decoded)
    if nodejs:
        print(f"  {nodejs}")


if __name__ == "__main__":
    main()
