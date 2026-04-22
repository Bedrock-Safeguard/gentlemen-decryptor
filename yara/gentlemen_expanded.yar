/*
    Bedrock Safeguard Inc. — The Gentlemen Ransomware
    Expanded Detection Rules (companion to gentlemen.yar)

    https://github.com/Bedrock-Safeguard/gentlemen-decryptor
    License: CC0 1.0

    Covers: adjacent tooling (EDR killer, SystemBC SOCKS5, staging scripts,
    BYOVD driver, affiliate phishing panel), plus process-memory detections
    for live-response triage.
*/

rule Gentlemen_KILLAV_Tool
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "The Gentlemen KILLAV helper — kills 12 security vendors before encryption"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "high"
        sample_sha256 = "7a311b584497e813"  /* partial, see RCMP report */
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $k1  = "SentinelOne"    ascii wide nocase
        $k2  = "CrowdStrike"    ascii wide nocase
        $k3  = "CarbonBlack"    ascii wide nocase
        $k4  = "Cylance"        ascii wide nocase
        $k5  = "SophosSED"      ascii wide nocase
        $k6  = "Malwarebytes"   ascii wide nocase
        $k7  = "McAfee"         ascii wide nocase
        $k8  = "TrendMicro"     ascii wide nocase
        $k9  = "Symantec"       ascii wide nocase
        $k10 = "ESET"           ascii wide nocase
        $k11 = "Kaspersky"      ascii wide nocase
        $k12 = "Cynet"          ascii wide nocase

        /* The Gentlemen-specific strings that appear alongside the vendor list */
        $cynet_tag  = "Cynet Ransom Protection" ascii
        $mp_exclude = "Add-MpPreference -ExclusionProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        8 of ($k*) and
        ($cynet_tag or $mp_exclude)
}

rule Gentlemen_SystemBC_Beacon
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "SystemBC SOCKS5 proxy as used by The Gentlemen (C2: 45.86.230.112:4001)"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "high"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $c2_ip      = "45.86.230.112"           ascii
        $c2_port    = "4001"                    ascii
        $socks_ua   = "SYSTEMBC"                ascii nocase
        $socks_cmd  = { 05 01 00 ?? ?? ?? ?? ?? 00 50 }  /* SOCKS5 handshake skeleton */
        $proxy_tag  = "socks5://"               ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (($c2_ip and $c2_port) or ($socks_ua and ($socks_cmd or $proxy_tag)))
}

rule Gentlemen_Packagec_Staging_PS1
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Packagec.ps1 staging script — downloads Dvx.zip from Vultr, runs h.exe, installs UpdateApp.bat persistence"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "critical"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $url      = "http://149.28.137.179/a/Dvx.zip"     ascii wide nocase
        $zip      = "Dvx.zip"                             ascii wide nocase
        $persist  = "UpdateApp.bat"                       ascii wide nocase
        $startup  = "\\Startup\\"                         ascii wide nocase
        $expand   = "Expand-Archive"                      ascii wide nocase
        $invoke_h = "h.exe"                               ascii wide nocase

    condition:
        filesize < 100KB and
        ($url or ($zip and $persist and $startup and $invoke_h))
}

rule Gentlemen_AK_Launcher_BAT
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "AK.bat launcher — hidden-window execution of Packagec.ps1"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "high"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $hidden   = "WindowStyle Hidden"    ascii nocase
        $bypass   = "-ExecutionPolicy Bypass" ascii nocase
        $pkg      = "Packagec.ps1"          ascii nocase
        $ps       = "powershell"            ascii nocase

    condition:
        filesize < 2KB and
        $hidden and $bypass and $pkg and $ps
}

rule Gentlemen_ThrottleStop_BYOVD
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "ThrottleStop.sys — vulnerable signed driver abused by Gentlemen operators (CVE-2025-7771)"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "critical"
        cve = "CVE-2025-7771"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $name  = "ThrottleStop" ascii wide nocase
        $drv   = "TechPowerUp"  ascii wide nocase   /* ThrottleStop publisher */
        $ioctl = { 22 A0 00 00 }                    /* characteristic IOCTL code for the CPU-tuning interface, abused in exploit */

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $name and ($drv or $ioctl)
}

rule Gentlemen_Werkzeug_Affiliate_Panel
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Packed Python/Flask/Werkzeug build matching Gentlemen affiliate phishing panel (Werkzeug/3.1.6 Python/3.11.9) — scans payloads dumped from memory"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "medium"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $wk1 = "Werkzeug/3.1.6 Python/3.11.9" ascii
        $wk2 = "Werkzeug/3.1.8 Python/3.9.25" ascii
        $faker = "fake.last_name()"           ascii   /* operator script signature */
        $apex = /\w+\.(stieglers\.net|isgedr\.org|pwtr\.art|s-hennebach\.de|tottimeths\.org\.uk|tigersafari\.us)/ ascii

    condition:
        filesize < 50MB and
        (1 of ($wk*)) and
        ($faker or $apex)
}

rule Gentlemen_Memory_LiveResponse
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Live-response memory scan — locate Gentlemen artifacts in an already-running process (for procdump/volatility/forensic triage)"
        date = "2026-04-21"
        yarahub_license = "CC0 1.0"
        severity = "high"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"

    strings:
        $m1 = "--marker--GENTLEMEN"                          ascii
        $m2 = "--eph--"                                      ascii
        $m3 = "negotiation_hapvida@proton.me"                ascii
        $m4 = "tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion" ascii
        $m5 = "chacha20: wrong HChaCha20 key size"           ascii
        $m6 = "crypto/ecdh: invalid private key size"        ascii
        $m7 = "LOCKER_BACKGROUND"                            ascii
        $m8 = "README-GENTLEMEN"                             ascii wide
        $m9 = "Cynet Ransom Protection"                      ascii

    condition:
        3 of ($m*)
}
