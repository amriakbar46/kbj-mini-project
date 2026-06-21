/*
   YARA rules for Case 3 (2025-06-13) PHP-based RAT with BYOI staging
   Bundle source: network-analysis/pcap/2025-06-13-traffic-analysis-exercise-forensic-analysis/
   Validated against: c2.exe (SHA256 1206473a7c...), config.cfg (SHA256 a24cda6f...), php.exe (SHA256 b0c32fba...)
   Author: re-analysis 2026-06-21
*/

import "pe"

rule PHP_RAT_config_cfg_case3
{
    meta:
        description = "PHP-based RAT C2 client (config.cfg from case3 2025-06-13)"
        author = "re-analysis"
        date = "2026-06-21"
        reference1 = "Discovered via analysis of 2025-06-13-traffic-analysis-exercise.pcap"
        sha256_known = "a24cda6fe5710272556b273d1b03081704a919130b5f10f18c7c16947f25d370"
        family_suspected = "Koi Loader / Koi RAT (PHP-based)"

    strings:
        // Encoding function (A2uxo)
        $enc_func1 = "gzencode" ascii
        $enc_func2 = "FORCE_GZIP" ascii
        $enc_func3 = "pack(\"V\"" ascii
        // C2 domain array variable
        $c2_array = "$h0b7d" ascii
        $fallback_array = "$b2dL6" ascii
        // 7 command codes (decode proof)
        $cmd_codes = "\"EXE\" => 0, \"DLL\" => 1, \"JS\" => 2, \"CMD\" => 3, \"ACTIVE\" => 4, \"AUTORUN\" => 5, \"OFF\" => 6" ascii
        // Persistence
        $persist1 = "CurrentVersion\\Run" ascii nocase
        $persist2 = "reg add HKCU" ascii nocase
        // Functions
        $fn_persist = "function UrHlx" ascii
        $fn_recon = "function mNFE9" ascii
        $fn_beacon = "function mOJ2M" ascii
        $fn_path = "function rxiXT" ascii
        $fn_xor = "function r7s9B" ascii
        $fn_crypt = "function A2uxo" ascii
        $fn_etupz = "function EtUpz" ascii
        // Recon commands
        $recon1 = "systeminfo" ascii
        $recon2 = "Get-Service" ascii
        $recon3 = "Get-NetNeighbor" ascii
        $recon4 = "tasklist /svc" ascii
        $recon5 = "WindowsPrincipal" ascii
        // Node.js cascade
        $nodejs1 = "nodejs.org/dist/v21.7.3" ascii
        $nodejs2 = "node-v21.7.3-win-x64" ascii
        // Goofy PHP string deobfuscation markers
        $goto1 = "goto " ascii

    condition:
        filesize < 100KB and
        (
            ($cmd_codes) or
            (
                3 of ($enc_func1, $enc_func2, $enc_func3, $c2_array, $fallback_array, $fn_persist, $fn_recon, $fn_beacon, $fn_path, $fn_xor, $fn_crypt, $fn_etupz, $persist1, $persist2, $recon1, $recon2, $recon3, $recon4, $recon5, $nodejs1, $nodejs2) and
                #goto1 >= 15
            )
        )
}

rule c2_exe_launcher_case3
{
    meta:
        description = "c2.exe launcher PE32+ (case3 2025-06-13, BYOI PHP RAT)"
        author = "re-analysis"
        date = "2026-06-21"
        sha256_known = "1206473a7c5643dc0a1a52c17418aa37fb5194e2395907aefaec976cb4849b4e"
        compiler = "GCC 14.2.0 (Rev2, Built by MSYS2 project)"
        compile_time = "2025-06-13T10:56:46Z"

    strings:
        // PowerShell stager payload embedded in UTF-16
        $ps_stager1 = "Invoke-RestMethod" ascii wide
        $ps_stager2 = "event-time-microsoft.org" ascii wide
        $ps_stager3 = "|clip" ascii wide
        $ps_stager4 = "Get-Clipboard" ascii wide
        $ps_stager5 = "[scriptblock]::Create" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        filesize == 17920 and
        3 of ($ps_stager*)
}

rule PHP_8_interpreter_unusual_location
{
    meta:
        description = "PHP 8 Windows interpreter in non-standard location (BYOI indicator)"
        author = "re-analysis"
        date = "2026-06-21"
        sha256_known = "b0c32fba80e2b15abb9e253c1d36e47383fad18940eab3c08e2c11c78803f133"
        note = "Generic rule - target detection by path, not just hash. Hash-based detection more reliable."

    strings:
        $php1 = "php.exe" ascii
        $php2 = "Zend" ascii
        $php3 = "PHP/" ascii wide
        $php4 = "TSRM" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 200KB and
        2 of them
}

rule truglomedspa_compromise_payload
{
    meta:
        description = "JavaScript payload from compromised truglomedspa.com (case3 2025-06-13)"
        author = "re-analysis"
        date = "2026-06-21"

    strings:
        $a1 = "window.commandGlobal" ascii
        $a2 = "powershell -w h -nop -c" ascii wide
        $a3 = "dng-,microsoftds,com" ascii wide
        $a4 = "Gsd" ascii wide
        $a5 = "DownloadString" ascii wide
        $a6 = "Invoke-Expression" ascii wide
        $a7 = "Net.WebClient" ascii wide
        $a8 = "event-time-microsoft.org" ascii wide
        $a9 = "hillcoweb.com" ascii wide

    condition:
        filesize < 100KB and
        4 of them
}
