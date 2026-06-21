#!/usr/bin/env python3
"""
case3_pe_analyzer.py — Full static PE analysis for c2.exe
Usage: python3 case3_pe_analyzer.py <path-to-c2.exe>

Performs:
  - Hash computation (MD5, SHA1, SHA256)
  - PE header inspection (machine, compile time, subsystem)
  - Section enumeration with entropy analysis
  - Import table extraction
  - Export table check
  - Resource directory inspection
  - Overlay data detection
  - Packer signature detection
  - ASCII & UTF-16 string extraction
  - File type identification (PE32+, x86-64, GUI/console)

Reference: Case 3 (2025-06-13) — BYOI PHP RAT with c2.exe launcher
Author: re-analysis 2026-06-21
"""

import sys
import re
import math
import datetime
import hashlib
from collections import Counter

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed. Install with:")
    print("  pip3 install --break-system-packages pefile")
    sys.exit(1)


PACKER_SIGNATURES = {
    b'UPX': 'UPX packer',
    b'MPRESS': 'MPRESS packer',
    b'ASPack': 'ASPack packer',
    b'PECompact': 'PECompact',
    b'Themida': 'Themida',
    b'VMProtect': 'VMProtect',
    b'MSVC': 'MSVC',
    b'GCC': 'GCC',
    b'MinGW': 'MinGW',
    b'.vmp0': 'Themida variant',
    b'.vmp1': 'Themida variant',
    b'.vmp2': 'Themida variant',
}


def compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 hashes."""
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
    }


def print_pe_header(pe: pefile.PE) -> None:
    """Print PE header details."""
    print("=" * 60)
    print("PE HEADER")
    print("=" * 60)
    machine_map = {0x8664: 'x86-64', 0x14c: 'x86', 0xaa64: 'ARM64'}
    machine = machine_map.get(pe.FILE_HEADER.Machine, f"unknown (0x{pe.FILE_HEADER.Machine:04x})")
    print(f"Machine        : 0x{pe.FILE_HEADER.Machine:04x} ({machine})")
    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        ts_str = datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat()
    except (ValueError, OSError):
        ts_str = f"invalid ({ts})"
    print(f"Compile time   : {ts} ({ts_str})")
    subsystem_map = {2: 'GUI', 3: 'CUI'}
    subsystem = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, 'unknown')
    print(f"Subsystem      : 0x{pe.OPTIONAL_HEADER.Subsystem:04x} ({subsystem})")
    print(f"Entry point    : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
    print(f"Image base     : 0x{pe.OPTIONAL_HEADER.ImageBase:016x}")
    print(f"DLL            : {'Yes' if pe.FILE_HEADER.Characteristics & 0x2000 else 'No'}")
    print(f"Stripped COFF  : {'Yes' if not hasattr(pe, 'DIRECTORY_ENTRY_SYMBOL') else 'No'}")


def print_sections(pe: pefile.PE) -> None:
    """Print sections with entropy and characteristics."""
    print("\n" + "=" * 60)
    print("SECTIONS")
    print("=" * 60)
    print(f"{'Name':<10} {'VAddr':>10} {'VSize':>10} {'RawSize':>10} {'Entropy':>8}  Notes")
    for sec in pe.sections:
        name = sec.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        entropy = sec.get_entropy()
        notes = []
        if entropy > 7.0:
            notes.append("HIGH ENTROPY (packed)")
        if sec.Characteristics & 0x20000000:
            notes.append("exec")
        if sec.Characteristics & 0x80000000:
            notes.append("write")
        if sec.Characteristics & 0x40000000:
            notes.append("read")
        if name in ('.text', '.rdata', '.data', '.rsrc', '.reloc'):
            notes.append({'.text': 'CODE', '.rdata': 'R/O DATA', '.data': 'INIT DATA',
                          '.rsrc': 'RESOURCES', '.reloc': 'RELOC'}[name])
        print(f"{name:<10} 0x{sec.VirtualAddress:08x} 0x{sec.Misc_VirtualSize:08x} "
              f"{sec.SizeOfRawData:>10,} {entropy:>8.3f}  {'; '.join(notes)}")


def print_imports(pe: pefile.PE) -> None:
    """Print imported DLLs and functions."""
    print("\n" + "=" * 60)
    print("IMPORTS")
    print("=" * 60)
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("  No imports")
        return
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('ascii', errors='replace')
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode('ascii', errors='replace'))
            else:
                funcs.append(f"ord{imp.ordinal}")
        print(f"  {dll} ({len(funcs)} funcs):")
        for fn in funcs:
            print(f"    - {fn}")


def print_exports(pe: pefile.PE) -> None:
    """Print exports if any."""
    print("\n" + "=" * 60)
    print("EXPORTS")
    print("=" * 60)
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("  No exports (typical for launcher/executable without DLL exports)")
        return
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode('ascii', errors='replace') if exp.name else f"ord{exp.ordinal}"
        print(f"  {name}: 0x{exp.address:08x}")


def print_resources(pe: pefile.PE) -> None:
    """Print resource directory if present."""
    print("\n" + "=" * 60)
    print("RESOURCES")
    print("=" * 60)
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print("  No resources")
        return
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        name = rsrc_type.name if rsrc_type.name else f"id={rsrc_type.id}"
        print(f"  Type: {name}")


def print_overlay(pe: pefile.PE, data: bytes) -> None:
    """Check for overlay data after PE structure."""
    print("\n" + "=" * 60)
    print("OVERLAY DATA")
    print("=" * 60)
    overlay_offset = pe.get_overlay_data_start_offset()
    if not overlay_offset:
        print("  No overlay data (file size matches PE structure exactly)")
        return
    overlay = data[overlay_offset:]
    print(f"  Offset: 0x{overlay_offset:08x}, Size: {len(overlay):,} bytes")
    counter = Counter(overlay)
    total = len(overlay)
    if total > 0:
        entropy = -sum((c/total) * math.log2(c/total) for c in counter.values() if c > 0)
        print(f"  Entropy: {entropy:.3f} ({'HIGH (encrypted/compressed)' if entropy > 7 else 'structured'})")
        print(f"  First 32 bytes: {overlay[:32].hex()}")


def print_packer_detection(data: bytes) -> None:
    """Scan for known packer signatures."""
    print("\n" + "=" * 60)
    print("PACKER SIGNATURES")
    print("=" * 60)
    strings_raw = re.findall(rb'[\x20-\x7e]{4,}', data)
    found = set()
    for s in strings_raw:
        for sig, name in PACKER_SIGNATURES.items():
            if sig in s:
                found.add(name)
    if found:
        for name in found:
            print(f"  Found: {name}")
    else:
        print("  No known packer signatures")


def print_ascii_strings(data: bytes, limit: int = 30) -> None:
    """Print top N longest ASCII strings."""
    print("\n" + "=" * 60)
    print(f"TOP {limit} LONGEST ASCII STRINGS")
    print("=" * 60)
    strings_raw = re.findall(rb'[\x20-\x7e]{4,}', data)
    ascii_strings = sorted(
        set(s.decode('ascii', errors='replace') for s in strings_raw if len(s) >= 6),
        key=len, reverse=True
    )
    for s in ascii_strings[:limit]:
        if len(s) < 200 and any(c.isalpha() for c in s):
            print(f"  [{len(s):4}] {s}")


def print_utf16_strings(data: bytes, limit: int = 20) -> None:
    """Print top N longest UTF-16 strings (often contains hidden payloads)."""
    print("\n" + "=" * 60)
    print(f"UTF-16 STRINGS (top {limit})")
    print("=" * 60)
    try:
        utf16_strings = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)
        utf16_decoded = sorted(
            set(s.decode('utf-16-le', errors='replace') for s in utf16_strings),
            key=len, reverse=True
        )
        for s in utf16_decoded[:limit]:
            if len(s) < 500:
                print(f"  [{len(s):4}] {s}")
    except Exception as e:
        print(f"  Error decoding UTF-16: {e}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-PE-file>")
        print(f"Example: {sys.argv[0]} /path/to/c2.exe")
        sys.exit(1)

    filepath = sys.argv[1]
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    print("=" * 60)
    print("FILE HASHES")
    print("=" * 60)
    hashes = compute_hashes(data)
    print(f"MD5    : {hashes['md5']}")
    print(f"SHA1   : {hashes['sha1']}")
    print(f"SHA256 : {hashes['sha256']}")
    print(f"Size   : {hashes['size']:,} bytes")

    pe = pefile.PE(data=data, fast_load=False)
    print_pe_header(pe)
    print_sections(pe)
    print_imports(pe)
    print_exports(pe)
    print_resources(pe)
    print_overlay(pe, data)
    print_packer_detection(data)
    print_ascii_strings(data)
    print_utf16_strings(data)


if __name__ == "__main__":
    main()
