"""Build MITRE ATT&CK Navigator JSON (1 combined layer for 3 cases).
Format compatible with https://mitre-attack.github.io/attack-navigator/
"""
import json
import sys
from datetime import datetime

# MITRE techniques per case (from incident reports Section 8)
TECHNIQUES = {
    "case1": {
        "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control", "score": 1, "comment": "HTTP POST to /foots.php and /index.php - direct IP C2 channel"},
        "T1102":    {"name": "Web Service", "tactic": "command-and-control", "score": 1, "comment": "Possible Adobe CDN dead-drop style lookup (acroipm2.adobe.com) - confidence medium"},
        "T1105":    {"name": "Ingress Tool Transfer", "tactic": "command-and-control", "score": 1, "comment": "C2 config response redirects to /index.php for secondary payload"},
        "T1036":    {"name": "Masquerading", "tactic": "defense-evasion", "score": 1, "comment": "Legacy Mozilla/4.0 MSIE 7.0 User-Agent on Windows 10.0"},
        "T1027":    {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "score": 1, "comment": "Encoded/encrypted body and binary blob with minimal readable strings"},
        "T1189":    {"name": "Drive-by Compromise", "tactic": "initial-access", "score": 1, "comment": "Hypothesis: malicious webpage or document with embedded download (no direct evidence in PCAP)"},
        "T1046":    {"name": "Network Service Discovery", "tactic": "discovery", "score": 1, "comment": "Lightweight: HTTP GET to Adobe CDN and Microsoft services for host enumeration (NCSI-like)"},
    },
    "case2": {
        "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control", "score": 1, "comment": "58 HTTP POST to /fakeurl.htm - direct IP C2 channel"},
        "T1219":    {"name": "Remote Access Software", "tactic": "command-and-control", "score": 1, "comment": "NetSupport Manager/1.3 User-Agent - commercial RAT abused as RAT"},
        "T1105":    {"name": "Ingress Tool Transfer", "tactic": "command-and-control", "score": 1, "comment": "Initial handshake body (250B) and response (152B) for tasking transfer"},
        "T1036":    {"name": "Masquerading", "tactic": "defense-evasion", "score": 1, "comment": "Endpoint /fakeurl.htm uses generic name to disguise C2 traffic"},
        "T1027":    {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "score": 1, "comment": "Body CMD=ENCD · ES=1 encoding on all beacon payloads"},
        "T1189":    {"name": "Drive-by Compromise", "tactic": "initial-access", "score": 1, "comment": "Hypothesis: social engineering or drive-by deploys NetSupport Manager client (no direct evidence in PCAP)"},
        "T1059":    {"name": "Command and Scripting Interpreter", "tactic": "execution", "score": 1, "comment": "Hypothesis: NetSupport Manager client may execute commands on victim (not visible in network traffic)"},
    },
    "case3": {
        "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control", "score": 1, "comment": "64 HTTP POST to 5 C2 domains (typosquat + Cloudflare tunnel)"},
        "T1090":    {"name": "Proxy", "tactic": "command-and-control", "score": 1, "comment": "Cloudflare Tunnel (trycloudflare.com) hides origin C2 IP"},
        "T1102":    {"name": "Web Service", "tactic": "command-and-control", "score": 1, "comment": "Use of oauth2.googleapis.com/token and aadcdn.msftauth.net in payload (confidence medium)"},
        "T1105":    {"name": "Ingress Tool Transfer", "tactic": "command-and-control", "score": 1, "comment": "Download 968.1 KB obfuscated PowerShell payload from 104.21.112.1"},
        "T1059.001":{"name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution", "score": 1, "comment": "WindowsPowerShell/5.1.26100.4202 User-Agent + 968KB PS script with Invoke-WebRequest, Compress-Archive, oauth2 token"},
        "T1036":    {"name": "Masquerading", "tactic": "defense-evasion", "score": 1, "comment": "Microsoft-like domain typosquatting: event-datamicrosoft.live, windows-msgas.com, event-time-microsoft.org"},
        "T1027":    {"name": "Obfuscated Files or Information", "tactic": "defense-evasion", "score": 1, "comment": "968KB obfuscated PS script with ${Get-...} variable manipulation (sandbox evasion)"},
        "T1041":    {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "score": 1, "comment": "URI pattern with &32-char-hex substring (MD5-like) suggests encoded data exfiltration - content not decoded"},
        "T1189":    {"name": "Drive-by Compromise", "tactic": "initial-access", "score": 1, "comment": "Hypothesis: malicious script delivered via phishing/document, executed via PowerShell (not visible in network)"},
        "T1046":    {"name": "Network Service Discovery", "tactic": "discovery", "score": 1, "comment": "POST to 10.6.13.129:5357/e762ae39-... (WSDAPI) - Windows Web Services on Devices API for local network enumeration"},
    },
}

# Tactic ordering (ATT&CK Enterprise)
TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def main():
    out_path = "output/mitre_attack_navigator.json"

    # Build combined techniques list with scoring based on # of cases
    # Score = number of cases that detected the technique
    technique_data = {}
    for case_id, techs in TECHNIQUES.items():
        for tid, tdata in techs.items():
            if tid not in technique_data:
                technique_data[tid] = {
                    "name": tdata["name"],
                    "tactic": tdata["tactic"],
                    "cases": [],
                    "comments": [],
                }
            technique_data[tid]["cases"].append(case_id)
            technique_data[tid]["comments"].append(f"[{case_id}] {tdata['comment']}")

    # Build ATT&CK Navigator layer JSON v4.5
    techniques_list = []
    for tid, tdata in sorted(technique_data.items()):
        # ATT&CK Navigator uses techniqueID like "T1071.001" - no period
        nav_tid = tid  # already in correct format
        techniques_list.append({
            "techniqueID": nav_tid,
            "tactic": tdata["tactic"],
            "score": len(tdata["cases"]),
            "color": "",
            "comment": f"Detected in {len(tdata['cases'])} case(s)\n\n" + "\n\n".join(tdata["comments"]),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False,
        })

    layer = {
        "name": "Mini Project - Network Traffic Analysis (3 Cases Union)",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Combined MITRE ATT&CK coverage from 3 PCAP cases (2024-09-04, 2024-11-26, 2025-06-13). "
            "Score = number of cases where technique was identified. "
            "Layer is suitable for upload to https://mitre-attack.github.io/attack-navigator/ "
            "via 'Open Existing Layer' > 'Upload from local'."
        ),
        "filters": {
            "platforms": ["Windows"],
        },
        "sorting": 0,
        "layout": "side",
        "hideDisable": False,
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#ffe766", "#ff6666", "#990000"],
            "minValue": 1,
            "maxValue": 3,
        },
        "legendItems": [
            {"label": "1 case", "color": "#ffe766"},
            {"label": "2 cases", "color": "#ff8c66"},
            {"label": "3 cases (all)", "color": "#990000"},
        ],
        "metadata": [
            {"name": "cases_detected", "value": ",".join(sorted(set(t for t in technique_data.keys() if len(technique_data[t]["cases"]) > 0)))[:200]},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    # Add attribution
    layer["_attribution"] = {
        "authors": ["6025252002 Kafiyatul Fithri", "6025252005 Dhayu Intan Nareswari",
                    "6025252014 Ridho Liwardana", "6025252010 Yoan Amri Akbar"],
        "generated_at": datetime.now().isoformat() + "Z",
        "source_pcap_count": 3,
        "source_pcap_files": [
            "pcap/2024-09-04-traffic-analysis-exercise.pcap",
            "pcap/2024-11-26-traffic-analysis-exercise.pcap",
            "pcap/2025-06-13-traffic-analysis-exercise.pcap",
        ],
    }

    with open(out_path, "w") as f:
        json.dump(layer, f, indent=2)

    # Print summary
    print(f"[OK] Saved {out_path}")
    print(f"     Total unique techniques: {len(technique_data)}")
    print(f"     All 3 cases: {sum(1 for t, d in technique_data.items() if len(d['cases']) == 3)}")
    print(f"     2 cases: {sum(1 for t, d in technique_data.items() if len(d['cases']) == 2)}")
    print(f"     1 case: {sum(1 for t, d in technique_data.items() if len(d['cases']) == 1)}")
    print(f"     Tactics covered: {sorted(set(d['tactic'] for d in technique_data.values()))}")
    print(f"\n[INFO] Upload to Navigator:")
    print(f"  1. Open https://mitre-attack.github.io/attack-navigator/")
    print(f"  2. Click '+ New Layer' > 'Open Existing Layer' > 'Upload from local'")
    print(f"  3. Select: {out_path}")


if __name__ == "__main__":
    main()
