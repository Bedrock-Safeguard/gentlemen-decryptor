# The Gentlemen Ransomware — Splunk SPL Queries

Bedrock Safeguard Inc. · CC0 1.0 · <https://github.com/Bedrock-Safeguard/gentlemen-decryptor>

Assumes Splunk Common Information Model (CIM) with **Sysmon** (index=sysmon or `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) and **DNS logs**. Adjust index names and sourcetypes for your environment.

---

## 1. Staging — AK.bat / Packagec.ps1 execution (Sysmon EventCode 1)

```spl
index=sysmon EventCode=1
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*AK.bat*" OR CommandLine="*Packagec.ps1*" OR CommandLine="*UpdateApp.bat*"
 OR CommandLine="*Dvx.zip*" OR CommandLine="*149.28.137.179*")
| table _time host User Image CommandLine ParentImage
```

## 2. Defender tampering with Gentlemen binary exclusion

```spl
index=sysmon EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe")
CommandLine="*Add-MpPreference*"
CommandLine="*-ExclusionProcess*"
(CommandLine="*hapvida*" OR CommandLine="*donavmp*" OR CommandLine="*gentle*"
 OR CommandLine="*alutech.exe*" OR CommandLine="*thegentlemansransomware*")
| table _time host User CommandLine ParentImage
```

## 3. ThrottleStop.sys driver load (Sysmon EventCode 6)

```spl
index=sysmon EventCode=6
ImageLoaded="*\\ThrottleStop.sys"
| table _time host ImageLoaded Signed SignatureStatus Signature
```

## 4. Ransom note or encrypted file footer (Sysmon EventCode 11)

```spl
index=sysmon EventCode=11
(TargetFilename="*README-GENTLEMEN*"
 OR TargetFilename="*LOCKER_BACKGROUND*"
 OR TargetFilename="*\\gentlemen.bmp"
 OR TargetFilename="*--fast--*"
 OR TargetFilename="*--ultra--*"
 OR TargetFilename="*--super--*")
| table _time host User Image TargetFilename
```

## 5. Outbound connection to known Gentlemen infrastructure

```spl
index=* sourcetype IN (stream:tcp stream:udp firewall pan_traffic cisco_asa sysmon)
| eval gentlemen_ips=split("91.107.247.163,45.86.230.112,149.28.137.179,176.120.22.52,176.120.22.127,176.120.22.131,176.120.22.239,176.120.22.6,176.120.22.42,176.120.22.61,176.120.22.73,193.143.1.53,193.143.1.197,91.212.166.228,91.212.166.229,91.212.166.140,91.212.166.39,91.212.166.206,91.212.166.114,91.212.166.238,91.212.166.239,91.212.166.225,91.212.166.16,91.212.166.35,91.212.166.227,91.212.166.237,91.212.166.180,91.212.166.202,91.212.166.125,45.134.26.39,45.134.26.88,45.134.26.43,45.134.26.159,45.134.26.154,45.134.26.236,45.86.230.6,45.86.230.107,45.86.230.178,194.213.18.16,194.213.18.90,194.213.18.115,194.213.18.164,194.213.18.194,194.213.18.217",",")
| where isnotnull(dest_ip) AND mvfind(gentlemen_ips, dest_ip) >= 0
| table _time src_ip src_user dest_ip dest_port app process_name
```

## 6. DNS query to any known phishing apex zone

```spl
index=dns sourcetype IN (bind:query infoblox:dns:query stream:dns Microsoft:dns:query)
| rex field=query "\.(?<apex>[^.]+\.[^.]+)$"
| eval apexes="stieglers.net isgedr.org leprended.com soflermance.com zhongshengshijia.com pwtr.art s-hennebach.de mymobilityltd.co.uk iggytheillustrator.co.uk farmacymru.org.uk saveloyfactory.co.uk southbucksbridgecentre.co.uk betapictures.us 1stafricanclothing.com larsbormann.de tottimeths.org.uk tigersafari.us cdbattery.org tomisho.info caterham.pro norc-us.org butternutpeeler.com a-bit-z.de lewesjoinery.co.uk plumbline.org.uk lugwash.org"
| where match(query, "(^|\.)(stieglers\.net|isgedr\.org|leprended\.com|soflermance\.com|zhongshengshijia\.com|pwtr\.art|s-hennebach\.de|mymobilityltd\.co\.uk|iggytheillustrator\.co\.uk|farmacymru\.org\.uk|saveloyfactory\.co\.uk|southbucksbridgecentre\.co\.uk|betapictures\.us|1stafricanclothing\.com|larsbormann\.de|tottimeths\.org\.uk|tigersafari\.us|cdbattery\.org|tomisho\.info|caterham\.pro|norc-us\.org|butternutpeeler\.com|a-bit-z\.de|lewesjoinery\.co\.uk|plumbline\.org\.uk|lugwash\.org)$")
| table _time src query record_type
```

## 7. Leak-site DNS query

```spl
index=dns
query="*tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad*"
| table _time src query
```

## 8. Persistence — UpdateApp.bat written to Startup folder

```spl
index=sysmon EventCode=11
TargetFilename="*\\Startup\\UpdateApp.bat"
| table _time host User Image TargetFilename
```

## 9. Prefetch wipe immediately followed by rare .exe creation

```spl
index=sysmon EventCode=1
CommandLine="*C:\\Windows\\Prefetch*" (CommandLine="*del *" OR CommandLine="*Remove-Item*" OR CommandLine="*erase *")
| eval wipe_time=_time
| join type=inner host [
    search index=sysmon EventCode=1
    (Image="*hapvida*" OR Image="*donavmp*" OR Image="*gentle.exe" OR Image="*alutech.exe")
    | eval exe_time=_time
    | table host Image exe_time ]
| where abs(exe_time - wipe_time) < 3600
| table _time host wipe_time exe_time Image CommandLine
```

## 10. Cynet bypass string on command line

```spl
index=sysmon EventCode=1 CommandLine="*Cynet Ransom Protection*"
| table _time host Image CommandLine
```

---

**Saved search recommendations:**
- Query 1, 2, 3, 4, 8, 10 → schedule every 15 minutes, alert on any match.
- Query 5 → schedule every 15 minutes, alert on any match (no tuning needed).
- Query 6 → schedule hourly. Alert above 3 events per device per hour.
- Query 7 → schedule daily. Any hit is critical.
- Query 9 → schedule every 30 minutes.
