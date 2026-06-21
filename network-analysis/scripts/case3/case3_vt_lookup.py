#!/usr/bin/env python3
"""
case3_vt_lookup.py — VirusTotal lookup for Case 3 forensic bundle
Usage: python3 case3_vt_lookup.py

Reads API key from .env file (one level up in network-analysis/).
Looks up: c2.exe, config.cfg, php.exe, payload 968KB.
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path


def load_api_key():
    """Load VT_API_KEY from .env file or environment variable.

    Searches for .env in this order:
      1. network-analysis/.env (project root, primary)
      2. ~/.env (user home fallback)
      3. Environment variable VT_API_KEY
    """
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent.parent / '.env',
        script_dir.parent / '.env',
        script_dir / '.env',
        Path.home() / '.env',
    ]
    for env_path in candidates:
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                value = value.strip().strip('"').strip("'")
                if key.strip() == 'VT_API_KEY' and value:
                    return value
    return os.environ.get('VT_API_KEY')


def compute_sha256(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def vt_lookup_file(api_key, filepath, label, vt_name_hint=None):
    """Look up a file hash on VirusTotal."""
    try:
        import vt
    except ImportError:
        print("ERROR: vt-py not installed. Run:")
        print("  pip3 install --break-system-packages vt-py")
        return None

    if not Path(filepath).exists():
        print(f"  [{label}] FILE NOT FOUND: {filepath}")
        return None

    sha256 = compute_sha256(filepath)
    print(f"\n[{label}]")
    print(f"  File:   {filepath}")
    print(f"  SHA256: {sha256}")

    try:
        client = vt.Client(api_key)
        try:
            file_obj = client.get_object(f'/files/{sha256}')
            print(f"  Found in VT database")

            stats = file_obj.last_analysis_stats
            print(f"  Detection: {stats.get('malicious', 0)}/{sum(stats.values())} engines flagged malicious")
            print(f"    Harmless:  {stats.get('harmless', 0)}")
            print(f"    Malicious: {stats.get('malicious', 0)}")
            print(f"    Suspicious: {stats.get('suspicious', 0)}")
            print(f"    Undetected: {stats.get('undetected', 0)}")
            print(f"    Timeout:    {stats.get('timeout', 0)}")
            print(f"    Type-unsupported: {stats.get('type-unsupported', 0)}")
            print(f"    Failure:     {stats.get('failure', 0)}")

            if file_obj.type_tag:
                print(f"  Type: {file_obj.type_tag}")
            if file_obj.size:
                print(f"  Size: {file_obj.size:,} bytes")
            if file_obj.magic:
                print(f"  Magic: {file_obj.magic}")
            if file_obj.trid:
                trid_lines = []
                for t in file_obj.trid[:3]:
                    if isinstance(t, dict):
                        trid_lines.append(f"{t.get('file_type', '?')} ({t.get('probability', 0):.1f}%)")
                    else:
                        trid_lines.append(str(t))
                print(f"  TRID (file type detection): {trid_lines}")
            if file_obj.tags:
                print(f"  Tags: {', '.join(file_obj.tags[:10])}")
            if file_obj.last_submission_date:
                print(f"  Last submission: {file_obj.last_submission_date}")
            if file_obj.times_submitted:
                print(f"  Times submitted: {file_obj.times_submitted}")

            ptc = file_obj.popular_threat_classification
            if ptc:
                try:
                    label_val = ptc.suggested_threat_label
                except AttributeError:
                    label_val = None
                if label_val:
                    print(f"  Suggested threat label: {label_val}")
                try:
                    cats = ptc.popular_threat_category
                except AttributeError:
                    cats = None
                if cats:
                    cat_strs = []
                    for c in cats[:5]:
                        if isinstance(c, dict):
                            cat_strs.append(c.get('value', str(c)))
                        else:
                            cat_strs.append(str(c))
                    print(f"  Threat categories: {', '.join(cat_strs)}")
                try:
                    names = ptc.popular_threat_name
                except AttributeError:
                    names = None
                if names:
                    name_strs = []
                    for n in names[:5]:
                        if isinstance(n, dict):
                            name_strs.append(n.get('value', str(n)))
                        else:
                            name_strs.append(str(n))
                    print(f"  Threat names: {', '.join(name_strs)}")

            top_results = []
            for engine_name, result in sorted(file_obj.last_analysis_results.items()):
                if result.category == 'malicious' or result.category == 'suspicious':
                    top_results.append((engine_name, result.result or 'detected', result.category))
            top_results.sort(key=lambda x: x[2] == 'malicious', reverse=True)
            if top_results:
                print(f"  Top detections (first 25):")
                for engine, result, category in top_results[:25]:
                    print(f"    [{category:10}] {engine:25}: {result}")

            return {
                'sha256': sha256,
                'stats': dict(stats),
                'type': getattr(file_obj, 'type_tag', None),
                'trid': getattr(file_obj, 'trid', []),
                'tags': getattr(file_obj, 'tags', []),
                'labels': [ptc.suggested_threat_label] if ptc and hasattr(ptc, 'suggested_threat_label') and ptc.suggested_threat_label else [],
            }
        except vt.error.APIError as e:
            if 'NotFoundError' in str(type(e)):
                print(f"  NOT FOUND in VT database (file may not have been submitted)")
                return None
            elif 'QuotaExceededError' in str(type(e)):
                print(f"  QUOTA EXCEEDED. Wait 1 minute and retry.")
                time.sleep(60)
                return vt_lookup_file(api_key, filepath, label)
            else:
                print(f"  API Error: {e}")
                return None
        finally:
            client.close()
    except Exception as e:
        print(f"  Error: {e}")
        return None


def main():
    api_key = load_api_key()
    if not api_key:
        print("ERROR: VT_API_KEY not found.")
        print("Set it in network-analysis/.env or as environment variable.")
        sys.exit(1)

    if len(api_key) != 64:
        print(f"WARNING: API key length is {len(api_key)} (expected 64 for VT API keys)")

    print("=" * 60)
    print(f"VIRUSTOTAL LOOKUP — Case 3 (2025-06-13) BYOI PHP RAT")
    print(f"API key: {api_key[:8]}...{api_key[-8:]} (redacted)")
    print("=" * 60)

    script_dir = Path(__file__).resolve().parent
    network_analysis_dir = script_dir.parent.parent
    bundle = network_analysis_dir / 'pcap' / '2025-06-13-traffic-analysis-exercise-forensic-analysis'
    output = network_analysis_dir / 'output' / 'case3' / 'payloads' / 'http_file_data'

    if not bundle.exists():
        print(f"WARNING: bundle not found at {bundle}")
        bundle_alt = network_analysis_dir / 'pcap' / '2025-06-13-traffic-analysis-exercise-forensic-analysis'
        if bundle_alt.exists():
            bundle = bundle_alt

    targets = [
        ('c2.exe (launcher)', bundle / 'AppData-Roaming-afUGkp' / 'c2.exe'),
        ('config.cfg (PHP RAT)', bundle / 'AppData-Roaming-php' / 'config.cfg'),
        ('php.exe (interpreter)', bundle / 'AppData-Roaming-php' / 'php.exe'),
        ('payload 968 KB', output / 'frame_8561_stream_90_104.21.112.1_to_10.6.13.133.bin'),
    ]

    results = {}
    for label, path in targets:
        if path.exists():
            r = vt_lookup_file(api_key, str(path), label)
            if r:
                results[label] = r
            time.sleep(4)
        else:
            print(f"\n[{label}] SKIPPED: file not found at {path}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for label, r in results.items():
        if r:
            stats = r['stats']
            mal = stats.get('malicious', 0)
            sus = stats.get('suspicious', 0)
            total = sum(stats.values())
            labels = r.get('labels', [])
            verdict = 'MALICIOUS' if mal > 0 else ('SUSPICIOUS' if sus > 0 else 'CLEAN')
            label_str = f" [{', '.join(labels)}]" if labels else ""
            print(f"  {label:30}: {verdict} ({mal}/{total} malicious){label_str}")
        else:
            print(f"  {label:30}: NOT FOUND / NOT SCANNED")


if __name__ == "__main__":
    main()
