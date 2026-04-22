# The Gentlemen Ransomware — Microsoft Defender KQL Queries

Bedrock Safeguard Inc. · CC0 1.0 · <https://github.com/Bedrock-Safeguard/gentlemen-decryptor>

Ready to paste into **Microsoft Defender 365 Advanced Hunting** or **Sentinel**. Tables referenced: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceImageLoadEvents`, `DnsEvents`.

---

## 1. Staging — AK.bat / Packagec.ps1 execution

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "AK.bat", "Packagec.ps1", "UpdateApp.bat",
    "149.28.137.179/a/Dvx.zip", "Dvx.zip"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId
```

## 2. Defender tampering with Gentlemen-adjacent binary exclusion

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
| where ProcessCommandLine has "Add-MpPreference"
| where ProcessCommandLine has "-ExclusionProcess"
| where ProcessCommandLine has_any (
    "hapvida", "donavmp", "gentle", "alutech.exe",
    "thegentlemansransomware", "gentlemen.bmp"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## 3. ThrottleStop.sys BYOVD loading (CVE-2025-7771)

```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "ThrottleStop.sys"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

## 4. Ransom note / encrypted file artifacts

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("FileCreated", "FileRenamed")
| where FileName contains "README-GENTLEMEN"
      or FileName endswith ".LOCKER_BACKGROUND"
      or FileName =~ "gentlemen.bmp"
      or FileName endswith "--fast--"
      or FileName endswith "--ultra--"
      or FileName endswith "--super--"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName
```

## 5. Outbound connection to known Gentlemen C2 / operator infra

```kql
let gentlemen_c2 = dynamic([
    // Live infrastructure confirmed April 2026
    "91.107.247.163",   // Cobalt Strike (Hetzner, DE)
    "45.86.230.112",    // SystemBC (BlueVPS, US)
    "149.28.137.179",   // Vultr staging (Packagec.ps1 source)
    // Proton66 operator cluster (40+ hosts across 4 subnets)
    "176.120.22.52", "176.120.22.127", "176.120.22.131", "176.120.22.239",
    "176.120.22.6", "176.120.22.42", "176.120.22.61", "176.120.22.73",
    "193.143.1.53", "193.143.1.197",
    "91.212.166.228", "91.212.166.229", "91.212.166.140", "91.212.166.39",
    "91.212.166.206", "91.212.166.114", "91.212.166.238", "91.212.166.239",
    "91.212.166.225", "91.212.166.16", "91.212.166.35", "91.212.166.227",
    "91.212.166.237", "91.212.166.180", "91.212.166.202", "91.212.166.125",
    "45.134.26.39", "45.134.26.88", "45.134.26.43", "45.134.26.159",
    "45.134.26.154", "45.134.26.236",
    // Phishing/mail botnet (BlueVPS + isgedr.org Mo's Operations block)
    "45.86.230.6", "45.86.230.107", "45.86.230.178",
    "194.213.18.16", "194.213.18.90", "194.213.18.115", "194.213.18.164",
    "194.213.18.194", "194.213.18.217"
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (gentlemen_c2)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol
```

## 6. DNS query to any of 26 known phishing apex zones

```kql
let gentlemen_apexes = dynamic([
    "stieglers.net","isgedr.org","leprended.com","soflermance.com",
    "zhongshengshijia.com","pwtr.art","s-hennebach.de","mymobilityltd.co.uk",
    "iggytheillustrator.co.uk","farmacymru.org.uk","saveloyfactory.co.uk",
    "southbucksbridgecentre.co.uk","betapictures.us","1stafricanclothing.com",
    "larsbormann.de","tottimeths.org.uk","tigersafari.us","cdbattery.org",
    "tomisho.info","caterham.pro","norc-us.org","butternutpeeler.com",
    "a-bit-z.de","lewesjoinery.co.uk","plumbline.org.uk","lugwash.org"
]);
DnsEvents
| where TimeGenerated > ago(30d)
| extend Apex = tostring(split(Name, ".")[-2]) + "." + tostring(split(Name, ".")[-1])
| where Apex in (gentlemen_apexes)
      or Name has_any (gentlemen_apexes)
| project TimeGenerated, Computer, ClientIP, Name, QueryType
```

## 7. Leak-site DNS query (Tor DoH/DoT leak)

```kql
DnsEvents
| where TimeGenerated > ago(90d)
| where Name has "tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad"
| project TimeGenerated, Computer, ClientIP, Name
```

## 8. Persistence — UpdateApp.bat in Startup folder

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName =~ "UpdateApp.bat"
      and FolderPath contains @"\Startup"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 9. Prefetch wipe immediately followed by rare .exe creation

```kql
let prefetchWipes =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine contains @"C:\Windows\Prefetch"
        and ProcessCommandLine has_any ("del ", "Remove-Item", "erase ")
    | project WipeTime=Timestamp, DeviceId, WipeCmd=ProcessCommandLine;
let rareExec =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName has_any ("hapvida", "donavmp", "gentle.exe", "alutech.exe");
prefetchWipes
| join kind=inner (rareExec) on DeviceId
| where abs(datetime_diff('second', WipeTime, Timestamp)) < 3600
| project WipeTime, Timestamp, DeviceId, WipeCmd, FileName, ProcessCommandLine
```

## 10. Cynet tampering — Gentlemen signature string

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "Cynet Ransom Protection"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

---

**Notes for tuning:**
- Queries default to 30 days. Adjust `ago(30d)` to your retention / investigation window.
- For high-volume environments, add device / user filters before the matching predicate.
- All detection logic is portable to Sentinel by changing `DeviceXxx` → `Sentinel`-equivalent tables (`SecurityEvent`, `CommonSecurityLog`, `Syslog`).
