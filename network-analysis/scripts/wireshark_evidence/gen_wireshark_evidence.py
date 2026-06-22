#!/usr/bin/env python3
"""Generate Wireshark-style evidence PNGs from tshark output for the NTA report.

Reproduces a packet-list-pane visualization (header bar, column headers,
alternating row colors, monospace font) of the data returned by tshark
for selected frame filters. Output PNGs are used as "screenshot evidence"
in the Final_Report_NTA Lampiran A.

Why render from tshark rather than Wireshark GUI screenshots:
  - Reproducible: re-run the script with the same PCAP and you get the
    same PNGs (modulo timestamps).
  - Headless: works on Linux without a display server.
  - Verifiable: every cell in the PNG corresponds to a tshark field that
    the reader can re-derive with the tshark command shown at the top of
    each PNG (see the title bar).
  - Self-documenting: the tshark -Y filter used is shown in the title
    bar of each PNG.

Usage:
  python3 gen_wireshark_evidence.py [--out-dir OUTPUT_DIR] [--pcap-dir PCAP_DIR]

Defaults assume the script is run from the repo root (where this file
lives under network-analysis/scripts/wireshark_evidence/) and the
PCAPs are at network-analysis/pcap/.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

HEADER_BG = "#d6e4f0"
ROW_BG_A = "#ffffff"
ROW_BG_B = "#f5f8fc"
TEXT = "#111"
BORDER = "#b8c4d1"
TITLE_BG = "#1f3a5f"


def get_tshark_fields(pcap, frame_filter, fields, extra_args=None):
    """Run tshark and return rows of fields joined by '|'."""
    cmd = ["tshark", "-r", pcap, "-Y", frame_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    if extra_args:
        cmd += extra_args
    cmd += ["-E", "separator=|"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not r.stdout.strip():
        return []
    return r.stdout.strip().split("\n")


def render_wireshark_pane(title, columns, rows, fname, out_dir,
                          max_rows=18, col_widths=None):
    """Render a Wireshark-style packet list pane as PNG.

    columns: list of (header_text, width_weight)
    rows: list of lists of strings (cell values)
    """
    n_cols = len(columns)
    n_rows = min(len(rows), max_rows)
    if n_rows == 0:
        return None

    if col_widths is None:
        total = sum(c[1] for c in columns)
        col_widths = [c[1] / total for c in columns]

    fig_w = 16
    fig_h = max(3.0, 0.42 * (n_rows + 3))
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Title bar
    ax.add_patch(Rectangle((0, 0.93), 1, 0.07, facecolor=TITLE_BG, edgecolor="none"))
    ax.text(0.005, 0.965, title, color="white", fontsize=10, family="monospace",
            weight="bold", va="center", ha="left")

    # Column headers
    header_y_top = 0.93
    header_h = 0.05
    x = 0
    for (header, _w), cw in zip(columns, col_widths):
        ax.add_patch(Rectangle((x, header_y_top - header_h), cw, header_h,
                               facecolor=HEADER_BG, edgecolor=BORDER, linewidth=0.5))
        ax.text(x + 0.005, header_y_top - header_h / 2, header, fontsize=8.5,
                family="monospace", weight="bold", va="center", ha="left", color=TEXT)
        x += cw

    # Body
    body_y_top = header_y_top - header_h
    row_h = body_y_top / (n_rows + 0.1)

    for ri in range(n_rows):
        row = rows[ri]
        y = body_y_top - (ri + 1) * row_h
        bg = ROW_BG_A if ri % 2 == 0 else ROW_BG_B
        ax.add_patch(Rectangle((0, y), 1, row_h, facecolor=bg, edgecolor="none"))

        x = 0
        for ci in range(n_cols):
            cell = row[ci] if ci < len(row) else ""
            if len(cell) > 90:
                cell = cell[:87] + "..."
            ax.add_patch(Rectangle((x, y), col_widths[ci], row_h, facecolor=bg,
                                   edgecolor=BORDER, linewidth=0.3))
            ax.text(x + 0.005, y + row_h / 2, cell, fontsize=7.5,
                    family="monospace", va="center", ha="left", color=TEXT)
            x += col_widths[ci]

    ax.add_patch(Rectangle((0, 0), 1, 0.005, facecolor=BORDER, edgecolor="none"))

    plt.tight_layout(pad=0)
    out_path = os.path.join(out_dir, fname)
    plt.savefig(out_path, dpi=130, bbox_inches="tight", facecolor="white")
    plt.close()
    return out_path


def find_first_tcp_stream(pcap, host_filter):
    """Return the TCP stream index of the first matching frame that has data.

    Skips streams with empty node info (Node 0/1 with :0 — these are control
    packets without real TCP stream, e.g. tshark internally uses some
    pseudo-streams for synchronization).
    """
    r = subprocess.run(
        ["tshark", "-r", pcap, "-Y", host_filter, "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, text=True,
    )
    if not r.stdout.strip():
        return None
    seen = set()
    for raw in r.stdout.strip().split("\n"):
        s = raw.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        verify = subprocess.run(
            ["tshark", "-r", pcap, "-q", "-z", f"follow,tcp,ascii,{s}"],
            capture_output=True, text=True,
        )
        if "Node 0: :0" in verify.stdout or "Node 1: :0" in verify.stdout:
            continue
        if "===" not in verify.stdout:
            continue
        return s
    return None


def get_follow_stream(pcap, stream_idx, max_bytes=4096):
    """Extract a TCP stream via tshark -z follow and split into client/server.

    Skips tshark header/footer lines (==, Follow:, Filter:, Node X:).
    Detects client vs server via a state machine:
      - First content block is always the client request (after header).
      - A tab-prefixed digit (\\t<num>) marks a server response length;
        lines after that until the next bare digit (client request length
        of a subsequent request) are server content.
      - A bare digit line (e.g. '443') marks a client request length;
        lines after that until the next \\t<num> are client content.
    Strips CR (\\r) from data lines.
    """
    r = subprocess.run(
        ["tshark", "-r", pcap, "-q", "-z", f"follow,tcp,ascii,{stream_idx}"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None, None

    client, server = [], []
    skip_prefixes = ("===", "Follow:", "Filter:", "Node 0:", "Node 1:")
    in_server_block = False

    for raw in r.stdout.split("\n"):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        if any(line.startswith(p) for p in skip_prefixes):
            in_server_block = False
            continue

        if line.startswith("\t"):
            in_server_block = True
            stripped = line.lstrip("\t").rstrip()
            if stripped and not stripped.isdigit():
                server.append(stripped)
            continue
        if line.strip().isdigit():
            in_server_block = False
            continue

        if in_server_block:
            server.append(line.rstrip())
        else:
            client.append(line.rstrip())

    return client[:max_bytes], server[:max_bytes]


def render_stream(pcap, stream_idx, title, fname, out_dir, max_lines=25):
    """Render a Wireshark Follow TCP Stream dialog as PNG.

    Client and server lines are rendered as two separate columns side by side
    (client on the left, server on the right) so the original Wireshark layout
    is preserved without any overlap.
    """
    client, server = get_follow_stream(pcap, stream_idx)
    if client is None:
        return None

    def wrap_lines(lines, width=70, limit=None):
        out = []
        for line in lines:
            if len(line) > width:
                for i in range(0, len(line), width):
                    out.append(line[i:i + width])
            else:
                out.append(line)
            if limit and len(out) >= limit:
                break
        return out

    c_lines = wrap_lines(client, limit=max_lines)[:22]
    s_lines = wrap_lines(server, limit=max_lines)[:22]

    n_rows = max(len(c_lines), len(s_lines), 1)
    fig_h = max(5.0, 0.30 * (n_rows + 5))
    fig, ax = plt.subplots(figsize=(14, fig_h))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.add_patch(Rectangle((0, 0.95), 1, 0.05, facecolor=TITLE_BG, edgecolor="none"))
    ax.text(0.005, 0.975, title, color="white", fontsize=10, family="monospace",
            weight="bold", va="center", ha="left")

    ax.add_patch(Rectangle((0.02, 0.91), 0.012, 0.022,
                           facecolor="#c43232", edgecolor="none"))
    ax.text(0.04, 0.92, "Client \u2192 Server (victim)", fontsize=8,
            family="monospace", va="center", ha="left")
    ax.add_patch(Rectangle((0.52, 0.91), 0.012, 0.022,
                           facecolor="#1d5d8f", edgecolor="none"))
    ax.text(0.54, 0.92, "Server \u2192 Client (C2)", fontsize=8,
            family="monospace", va="center", ha="left")

    col_separator = 0.5
    y_top = 0.88
    row_h = 0.026

    for ri, line in enumerate(c_lines):
        y = y_top - (ri + 1) * row_h
        if ri % 2 == 0:
            ax.add_patch(Rectangle((0, y), col_separator, row_h,
                                   facecolor="#fdf5f5", edgecolor="none"))
        ax.text(0.005, y + row_h / 2, line, fontsize=7, family="monospace",
                color="#c43232", va="center", ha="left")

    for ri, line in enumerate(s_lines):
        y = y_top - (ri + 1) * row_h
        if ri % 2 == 0:
            ax.add_patch(Rectangle((col_separator, y), 1 - col_separator, row_h,
                                   facecolor="#f5f8fc", edgecolor="none"))
        ax.text(col_separator + 0.005, y + row_h / 2, line, fontsize=7,
                family="monospace", color="#1d5d8f", va="center", ha="left")

    ax.add_patch(Rectangle((col_separator - 0.001, 0), 0.002, 0.9,
                           facecolor="#cccccc", edgecolor="none"))

    plt.tight_layout(pad=0)
    out_path = os.path.join(out_dir, fname)
    plt.savefig(out_path, dpi=130, bbox_inches="tight", facecolor="white")
    plt.close()
    return out_path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--pcap-dir", default=None,
        help="Directory containing the 3 case PCAPs. If not specified, "
             "auto-detect: tries network-analysis/pcap relative to the script location.",
    )
    parser.add_argument(
        "--out-dir", default=None,
        help="Output directory for PNGs. If not specified, auto-detect: "
             "<script_dir>/output/ (this folder is committed to GitHub).",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root_candidate = script_dir.parent.parent.parent

    if args.pcap_dir:
        pcap_dir = Path(args.pcap_dir).resolve()
    else:
        pcap_dir = (repo_root_candidate / "network-analysis" / "pcap").resolve()

    if args.out_dir:
        out_dir = Path(args.out_dir).resolve()
    else:
        out_dir = (script_dir / "output").resolve()

    out_dir.mkdir(parents=True, exist_ok=True)

    pcap1 = pcap_dir / "2024-09-04-traffic-analysis-exercise.pcap"
    pcap2 = pcap_dir / "2024-11-26-traffic-analysis-exercise.pcap"
    pcap3 = pcap_dir / "2025-06-13-traffic-analysis-exercise.pcap"

    if not pcap3.exists():
        # Try unzipped fallback
        for name in os.listdir(pcap_dir):
            if "2025-06-13" in name and name.endswith(".pcap"):
                pcap3 = pcap_dir / name
                break

    print(f"PCAP 1: {pcap1}")
    print(f"PCAP 2: {pcap2}")
    print(f"PCAP 3: {pcap3}")
    print(f"Output: {out_dir}\n")

    # === Case 1 ===
    print("Case 1: HTTP beacon evidence...")
    rows = get_tshark_fields(
        str(pcap1),
        "http.request and ip.dst == 79.124.78.197",
        ["frame.number", "frame.time_relative", "ip.dst", "http.request.method",
         "http.request.uri", "http.user_agent"],
    )
    parsed = [r.split("|") for r in rows[:15]]
    p = render_wireshark_pane(
        "tshark -Y \"http.request and ip.dst == 79.124.78.197\" \u2014 case1 C2 HTTP beacon (Bulgaria)",
        [("No.", 6), ("Time (s)", 10), ("Destination", 14), ("Method", 7),
         ("URI", 30), ("User-Agent", 50)],
        parsed, "case1_c2_http_beacon.png", str(out_dir), max_rows=15,
    )
    if p:
        print(f"  wrote {p}")

    # === Case 2 ===
    print("Case 2: NetSupport RAT evidence...")
    rows = get_tshark_fields(
        str(pcap2),
        "http.request and ip.dst == 194.180.191.64",
        ["frame.number", "frame.time_relative", "ip.dst", "http.request.method",
         "http.request.uri", "http.user_agent"],
    )
    parsed = [r.split("|") for r in rows[:15]]
    p = render_wireshark_pane(
        "tshark -Y \"http.request and ip.dst == 194.180.191.64\" \u2014 case2 C2 HTTP beacon (Moldova)",
        [("No.", 6), ("Time (s)", 10), ("Destination", 14), ("Method", 7),
         ("URI", 30), ("User-Agent", 50)],
        parsed, "case2_c2_http_beacon.png", str(out_dir), max_rows=15,
    )
    if p:
        print(f"  wrote {p}")

    # === Case 3 ===
    print("Case 3: BYOI PHP RAT evidence...")

    # 3a. Initial stager (frames 6642 + 6699)
    rows = get_tshark_fields(
        str(pcap3),
        "frame.number == 6642 or frame.number == 6699",
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
         "_ws.col.Protocol", "http.request.method", "http.host", "http.request.uri",
         "http.user_agent"],
    )
    parsed = [r.split("|") for r in rows]
    p = render_wireshark_pane(
        "tshark -Y \"frame.number == 6642 or frame.number == 6699\" \u2014 case3 Initial Stager",
        [("No.", 6), ("Time (s)", 10), ("Source", 13), ("Destination", 13),
         ("Proto", 7), ("Method", 7), ("Host", 30), ("URI", 22), ("User-Agent", 30)],
        parsed, "case3_initial_stager.png", str(out_dir), max_rows=10,
    )
    if p:
        print(f"  wrote {p}")

    # 3b. BYOI TLS (frame 8569)
    rows = get_tshark_fields(
        str(pcap3),
        "frame.number == 8569",
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
         "_ws.col.Protocol", "tls.handshake.extensions_server_name"],
    )
    parsed = [r.split("|") for r in rows]
    p = render_wireshark_pane(
        "tshark -Y \"frame.number == 8569\" \u2014 case3 BYOI TLS (windows.php.net)",
        [("No.", 6), ("Time (s)", 10), ("Source", 13), ("Destination", 13),
         ("Proto", 8), ("SNI (TLS Server Name Indication)", 60)],
        parsed, "case3_byoi_tls.png", str(out_dir), max_rows=5,
    )
    if p:
        print(f"  wrote {p}")

    # 3c. First C2 beacon (windows-msgas.com)
    rows = get_tshark_fields(
        str(pcap3),
        'http.request and http.host == "windows-msgas.com" and frame.number < 45000',
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
         "http.request.method", "http.host", "http.request.uri", "http.content_type"],
    )
    parsed = [r.split("|") for r in rows[:10]]
    p = render_wireshark_pane(
        "tshark -Y 'http.request and http.host == \"windows-msgas.com\"' \u2014 case3 First C2 beacon",
        [("No.", 6), ("Time (s)", 10), ("Source", 13), ("Destination", 13),
         ("Method", 7), ("Host", 22), ("URI", 35), ("Content-Type", 25)],
        parsed, "case3_first_c2_beacon.png", str(out_dir), max_rows=10,
    )
    if p:
        print(f"  wrote {p}")

    # 3d. Multi-domain C2 rotation
    rows = get_tshark_fields(
        str(pcap3),
        "http.request and (http.host == \"windows-msgas.com\" or "
        "http.host == \"event-datamicrosoft.live\" or "
        "http.host contains \"trycloudflare.com\")",
        ["frame.number", "frame.time_relative", "http.host", "http.request.method",
         "http.request.uri", "http.content_type", "http.user_agent"],
    )
    parsed = [r.split("|") for r in rows[:15]]
    p = render_wireshark_pane(
        "tshark -Y 'http.request and (host == windows-msgas / event-datamicrosoft / trycloudflare)' \u2014 case3 Multi-domain C2",
        [("No.", 6), ("Time (s)", 10), ("Host", 35), ("Method", 7),
         ("URI", 40), ("Content-Type", 20), ("User-Agent", 18)],
        parsed, "case3_multi_domain_c2.png", str(out_dir), max_rows=15,
    )
    if p:
        print(f"  wrote {p}")

    # 3e. DNS queries to C2 domains
    rows = get_tshark_fields(
        str(pcap3),
        "dns.qry.name and (dns.qry.name == \"windows-msgas.com\" or "
        "dns.qry.name == \"event-datamicrosoft.live\" or "
        "dns.qry.name == \"event-time-microsoft.org\" or "
        "dns.qry.name == \"eventdata-microsoft.live\" or "
        "dns.qry.name == \"windows.php.net\" or "
        "dns.qry.name contains \"trycloudflare.com\")",
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
         "dns.qry.name", "dns.a"],
    )
    parsed = [r.split("|") for r in rows[:15]]
    p = render_wireshark_pane(
        "tshark -Y 'dns.qry.name matches (3 C2 + 2 stager + BYOI)' \u2014 case3 DNS queries",
        [("No.", 6), ("Time (s)", 10), ("Source", 13), ("Destination", 13),
         ("Query", 35), ("Resolved A", 18)],
        parsed, "case3_dns_c2_queries.png", str(out_dir), max_rows=15,
    )
    if p:
        print(f"  wrote {p}")

    # 3f. WSDAPI (benign baseline)
    rows = get_tshark_fields(
        str(pcap3),
        "http.request and ip.dst == 10.6.13.129",
        ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
         "http.request.method", "http.request.uri", "http.user_agent"],
    )
    parsed = [r.split("|") for r in rows[:6]]
    p = render_wireshark_pane(
        "tshark -Y \"http.request and ip.dst == 10.6.13.129\" \u2014 case3 WSDAPI (benign, NOT an IOC)",
        [("No.", 6), ("Time (s)", 10), ("Source", 13), ("Destination", 13),
         ("Method", 7), ("URI", 35), ("User-Agent", 30)],
        parsed, "case3_wsdapi_benign.png", str(out_dir), max_rows=6,
    )
    if p:
        print(f"  wrote {p}")

    # === Follow TCP Stream views ===
    print("\nFollow TCP Stream views...")

    # Case 1
    stream = find_first_tcp_stream(
        str(pcap1),
        'http.request and http.request.uri contains "/foots.php"',
    )
    if stream:
        p = render_stream(
            str(pcap1), stream,
            f"tshark -z follow,tcp,ascii,{stream} \u2014 case1 Follow TCP Stream (POST /foots.php)",
            "case1_follow_stream.png", str(out_dir),
        )
        if p:
            print(f"  wrote {p}")

    # Case 2
    stream = find_first_tcp_stream(
        str(pcap2),
        'http.request and http.user_agent contains "NetSupport"',
    )
    if stream:
        p = render_stream(
            str(pcap2), stream,
            f"tshark -z follow,tcp,ascii,{stream} \u2014 case2 Follow TCP Stream (NetSupport POST)",
            "case2_follow_stream.png", str(out_dir),
        )
        if p:
            print(f"  wrote {p}")

    # Case 3 — Initial stager (stream 89)
    p = render_stream(
        str(pcap3), "89",
        "tshark -z follow,tcp,ascii,89 \u2014 case3 Follow TCP Stream (Initial Stager: event-time-microsoft.org)",
        "case3_follow_stream_stager.png", str(out_dir),
    )
    if p:
        print(f"  wrote {p}")

    # Case 3 — first C2 beacon to windows-msgas
    stream = find_first_tcp_stream(
        str(pcap3),
        'http.request and http.host == "windows-msgas.com"',
    )
    if stream:
        p = render_stream(
            str(pcap3), stream,
            f"tshark -z follow,tcp,ascii,{stream} \u2014 case3 Follow TCP Stream (First C2 beacon)",
            "case3_follow_stream_c2_beacon.png", str(out_dir),
        )
        if p:
            print(f"  wrote {p}")

    print(f"\nDone. PNGs written to {out_dir}")


if __name__ == "__main__":
    main()
