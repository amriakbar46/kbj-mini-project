#!/usr/bin/env python3
"""
case3_yara_validator.py — Validate YARA rules against forensic bundle
Usage: python3 case3_yara_validator.py <path-to-yara.yar> <bundle-dir>

Validates all YARA rules in the .yar file against:
  - c2.exe
  - config.cfg
  - php.exe
  - ycBFVIbLl.lnk (both copies)
  - Payload 968 KB
  - Edge cache files

Prints match results for each file.
"""

import os
import sys
import hashlib
import json


def compute_sha256(filepath: str) -> str:
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def find_bundle_files(bundle_dir: str) -> list:
    """Find all relevant forensic bundle files."""
    candidates = [
        ('c2.exe (afUGkp)', os.path.join(bundle_dir, 'AppData-Roaming-afUGkp', 'c2.exe')),
        ('c2.exe hash reference', None),
        ('config.cfg', os.path.join(bundle_dir, 'AppData-Roaming-php', 'config.cfg')),
        ('php.exe', os.path.join(bundle_dir, 'AppData-Roaming-php', 'php.exe')),
        ('ycBFVIbLl.lnk (afUGkp)', os.path.join(bundle_dir, 'AppData-Roaming-afUGkp', 'ycBFVIbLl.lnk')),
        ('ycBFVIbLl.lnk (Startup)', os.path.join(bundle_dir, 'AppData-Roaming-Microsoft-Windows-Start_Menu-Programs-Startup', 'ycBFVIbLl.lnk')),
        ('Edge cache (truglomedspa.com)', os.path.join(bundle_dir, 'Results-from-ChromeCacheView', '2025-06-13-033443-UTC-from-www.truglomedsp_com.txt')),
        ('Edge cache (hillcoweb JS)', os.path.join(bundle_dir, 'Results-from-ChromeCacheView', '2025-06-13-033446-UTC-from-hillcoweb_com_5h7o.js.txt')),
        ('Edge cache (URL list)', os.path.join(bundle_dir, 'Results-from-ChromeCacheView', '2025-06-13-033449-UTC-from-hillcoweb_com-URL.txt')),
        ('Edge cache events', os.path.join(bundle_dir, 'Results-from-ChromeCacheView', '2025-06-13-ChromeCacheView-events-from-Edge-Browser.txt')),
        ('forensic notes', os.path.join(bundle_dir, '2025-06-25-forensic-notes.txt')),
    ]
    return candidates


def find_payload_968kb(workspace_root: str) -> str:
    """Find the 968 KB payload file in standard locations."""
    import subprocess
    try:
        result = subprocess.run(
            ['find', workspace_root, '-name', 'frame_8561*stream_90*', '-type', 'f'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]
    except Exception:
        pass
    return None


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <yara-rules.yar> <bundle-dir> [workspace-root]")
        print(f"Example: {sys.argv[0]} case3_yara_rules.yar /path/to/forensic-analysis/ /path/to/workspace")
        sys.exit(1)

    yara_path = sys.argv[1]
    bundle_dir = sys.argv[2]
    workspace_root = sys.argv[3] if len(sys.argv) > 3 else os.path.dirname(bundle_dir)

    try:
        import yara
    except ImportError:
        print("ERROR: yara-python not installed. Install with:")
        print("  pip3 install --break-system-packages yara-python")
        sys.exit(1)

    # Known SHA256 hashes for verification
    known_hashes = {
        'c2.exe (afUGkp)': '1206473a7c5643dc0a1a52c17418aa37fb5194e2395907aefaec976cb4849b4e',
        'config.cfg': 'a24cda6fe5710272556b273d1b03081704a919130b5f10f18c7c16947f25d370',
        'php.exe': 'b0c32fba80e2b15abb9e253c1d36e47383fad18940eab3c08e2c11c78803f133',
    }

    # Compile YARA rules
    try:
        rules = yara.compile(filepath=yara_path)
        print(f"OK YARA rules compiled from {yara_path}\n")
    except yara.SyntaxError as e:
        print(f"FAIL YARA syntax error: {e}")
        sys.exit(1)

    # Find and scan files
    files_to_scan = find_bundle_files(bundle_dir)

    # Add 968 KB payload if found
    payload_path = find_payload_968kb(workspace_root)
    if payload_path:
        files_to_scan.append(('payload 968 KB', payload_path))

    print("=" * 80)
    print("YARA RULE VALIDATION (against forensic bundle)")
    print("=" * 80)

    for name, path in files_to_scan:
        if path is None:
            continue
        if not os.path.exists(path):
            print(f"\n[{name}]  FILE NOT FOUND: {path}")
            continue

        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"\n[{name}]  READ ERROR: {e}")
            continue

        actual_sha = hashlib.sha256(data).hexdigest()
        expected_sha = known_hashes.get(name)
        sha_match = "OK" if expected_sha is None or actual_sha == expected_sha else "MISMATCH"

        matches = rules.match(data=data)
        rule_names = sorted({m.rule for m in matches})

        print(f"\n[{name}]")
        print(f"  Path:   {path}")
        print(f"  SHA256: {actual_sha[:32]}... [{sha_match}]")
        print(f"  Size:   {len(data):,} bytes")
        if rule_names:
            for rn in rule_names:
                print(f"  MATCH: {rn}")
        else:
            print(f"  - (no rule match)")


if __name__ == "__main__":
    main()
