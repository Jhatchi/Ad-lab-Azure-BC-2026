# 04. Red / Blue Bonus Techniques (5)

Five offensive techniques run on the lab as a purple-team exercise. Each is documented as a complete chain : reconnaissance, trigger, captured detection event, and the native detection event mapping. All commands ran inside the lab. None of these techniques required Mimikatz, Rubeus, Impacket, or any other third-party offensive tool : pure PowerShell and built-in Windows utilities.

> The point of running these without third-party tools is to demonstrate that signature-based detection (block `mimikatz.exe`, block `Rubeus.exe`) is insufficient. All five techniques here would evade an AV that only knows offensive tool signatures, yet all five generate behavioural signals that the lab's logging chain caught.

---

## Technique 1 : Kerberoasting

**MITRE :** T1558.003 Steal or Forge Kerberos Tickets : Kerberoasting

### Reconnaissance (hunting query)

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName, PasswordLastSet |
  Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet
```

Initial output before the lab added a test SPN : only `krbtgt` had a ServicePrincipalName. The 3 lab service accounts (`svc_backup`, `svc_ftp`, `svc_monitor`) had none. This is realistic : Kerberoasting depends on service accounts being SPN-decorated, which happens in the wild when a real service is registered.

### Pre-positioning : adding a SPN

```powershell
Set-ADUser -Identity svc_backup `
  -ServicePrincipalNames @{Add="HTTP/becode-backup.becode.corp.lab"}
```

### Trigger (the attack)

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
  -ArgumentList "HTTP/becode-backup.becode.corp.lab"
```

The token output included :

```
Id                   : {REDACTED}
ValidFrom            : 24/03/2026 13:23:00
ValidTo              : 24/03/2026 23:18:18    # ~10h validity, fixed by KDC
ServicePrincipalName : HTTP/becode-backup.becode.corp.lab
```

### Captured output : Event 4769

```
EventID : 4769 (Kerberos service ticket requested)

Account Information :
  Account Name   : azureadmin@BECODE.CORP.LAB
  Account Domain : BECODE.CORP.LAB

Service Information :
  Service Name   : svc_backup
  Service ID     : BECODE\svc_backup
  Available Keys : RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256, AES256-SHA384

Network Information :
  Client Address : ::1                            # local DC, loopback
  Client Port    : 0

Additional Information :
  Ticket Options         : 0x40810000
  Ticket Encryption Type : 0x17                   # RC4-HMAC (Kerberoasting indicator)
  Failure Code           : 0x0                    # success, ticket issued
```

### Key indicators

- `Ticket Encryption Type = 0x17` is the canonical Kerberoasting flag (RC4 instead of AES).
- The service account had AES256 available, but the attacker tool deliberately requested RC4 (weaker, faster to crack offline).
- `Failure Code 0x0` confirms the ticket was issued, giving the attacker encrypted material to crack offline with Hashcat.

### Detection logic

```
Event Log : Security (DC)
Event ID  : 4769
Conditions :
  AND Ticket_Encryption_Type = "0x17"
  AND Service_Name NOT ENDS WITH "$"
  AND Service_Name NOT IN known_service_accounts_with_legitimate_RC4
```

Proactive complement (the hunting query shown above) lets a defender spot accounts that are Kerberoastable before they get attacked.

---

## Technique 2 : AS-REP Roasting

**MITRE :** T1558.004 Steal or Forge Kerberos Tickets : AS-REP Roasting

### Pre-positioning

In `dsa.msc`, on the user properties for `svc_ftp`, Account tab > Account options, the "Do not require Kerberos preauthentication" checkbox was enabled. This is the well-hidden toggle noted in `02-build-walkthrough.md`.

### Trigger

A normal Kerberos AS-REQ for `svc_ftp` (the request itself does not need to come from a privileged account). With pre-auth disabled, the KDC will issue a TGT without verifying the requester knows the account's password. The encrypted TGT can then be cracked offline.

### Captured output : Event 4768

Full XML structure was not preserved, but the decisive fields were :

- `Account Name : svc_ftp`
- `Pre-Authentication Type : 0` (normal would be `2`)
- `Result Code : 0x0` (success, TGT issued without authenticating the requester)

The combination of pre-auth type 0 plus result 0x0 confirms textbook AS-REP Roasting conditions.

### Proactive hunt

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
  -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName
```

Any account returned by this query is a candidate target. Schedule this as a daily blue-team query.

### Detection logic

```
Event Log : Security (DC)
Event ID  : 4768
Conditions :
  AND Pre_Authentication_Type = "0"
  AND Result_Code = "0x0"
```

---

## Technique 3 : AD Enumeration via PowerShell

**MITRE :** T1087.002 Account Discovery : Domain Account + T1069.002 Permission Groups Discovery : Domain Groups

### Trigger

```powershell
Get-ADComputer -Filter * | Select-Object Name, DNSHostName
Get-ADGroup    -Filter * | Select-Object Name, GroupScope
```

These are LDAP-equivalent queries. The DC sees the LDAP traffic but not the original PowerShell command unless ScriptBlock logging is enabled on the originating host.

### Captured output : Event 4104

```
ScriptBlock text (1 of 1) :
Get-ADComputer -Filter * | Select-Object Name, DNSHostName

ScriptBlock ID : {REDACTED}
```

```
ScriptBlock text (1 of 1) :
Get-ADGroup -Filter * | Select-Object Name, GroupScope

ScriptBlock ID : {REDACTED}
```

### Cross-host observation

From `ws01`, `leo.simon` ran `net user /domain` and `net group /domain` from `cmd.exe`. These commands were captured on `ws01` by Sysmon Event 1 (process creation with full command line) but did NOT generate corresponding Event 4768 on the DC, because `net user /domain` uses LDAP, not Kerberos directly. Native Windows logging gives only partial coverage on those commands. This justifies Sysmon on workstations.

### Detection logic

```
Event Log : Microsoft-Windows-PowerShell/Operational
Event ID  : 4104
Conditions :
  Script_Block_Text MATCHES ANY OF
    "Get-ADComputer -Filter",
    "Get-ADUser -Filter",
    "Get-ADGroup -Filter",
    "Get-ADGroupMember",
    "[adsisearcher]"

Complementary :
  Event Log : Microsoft-Windows-Sysmon/Operational (workstation)
  Event ID  : 1
  Conditions :
    Image ENDS WITH "\net.exe"
    AND CommandLine MATCHES "(?i)(user|group)\s+/domain"
```

---

## Technique 4 : LSASS Memory Dump

**MITRE :** T1003.001 OS Credential Dumping : LSASS Memory

### Trigger

From Task Manager, Details tab, right-click `lsass.exe` > Create dump file. This produces a memory dump of LSASS at `%LOCALAPPDATA%\Temp\lsass.DMP`, which an attacker can then exfiltrate and crack offline.

### Captured output : Sysmon Event 11

```
File created :
  RuleName        : -
  UtcTime         : 2026-03-24 13:57:13.947
  ProcessId       : 616
  Image           : C:\Windows\system32\taskmgr.exe
  TargetFilename  : C:\Users\AZUREA~1\AppData\Local\Temp\lsass.DMP
  CreationUtcTime : 2026-03-24 13:57:13.946
  User            : BECODE\azureadmin
```

### Critical observation

Sysmon Event 10 (Process Access on `lsass.exe`) was NOT triggered. The SwiftOnSecurity config explicitly whitelists Task Manager as a known-legitimate accessor of LSASS. Detection still worked through Event 11 (File Create) on the `lsass.DMP` filename pattern.

This is a real-world LOLBin (Living Off the Land Binary) lesson. Adversaries who know the SwiftOnSecurity whitelist can use Task Manager as an LSASS dumping tool and bypass the Event 10 detection. Production environments running SwiftOnSecurity should consider tightening the whitelist for Tier 0 hosts.

### Detection logic

```
Primary :
  Event Log : Microsoft-Windows-Sysmon/Operational
  Event ID  : 10
  Conditions :
    TargetImage = "C:\Windows\System32\lsass.exe"
    AND GrantedAccess IN ["0x1010", "0x1410", "0x1438", "0x143A", "0x1FFFFF"]
    AND SourceImage NOT IN known_legitimate_processes

Backup (file artifact, the path that worked in this lab when Event 10 was filtered) :
  Event Log : Microsoft-Windows-Sysmon/Operational
  Event ID  : 11
  Conditions :
    TargetFilename MATCHES "*lsass*.DMP" OR "*lsass*.dmp"
```

---

## Technique 5 : Lateral Movement via PSRemoting

**MITRE :** T1021.006 Remote Services : Windows Remote Management

### Trigger

From `dc01`, after the PSRemoting prep documented in `02-build-walkthrough.md` :

```powershell
$cred = Get-Credential
Enter-PSSession -ComputerName ws01.becode.corp.lab -Credential $cred
```

### Captured output : Sysmon Event 3

```
Network connection detected :
  UtcTime             : 2026-03-24 14:36:53.145
  ProcessId           : 9960
  Image               : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  User                : BECODE\azureadmin
  Protocol            : tcp
  Initiated           : true                              # outbound from dc01
  SourceIp            : <DC_PRIVATE_IP>
  SourceHostname      : dc01.becode.corp.lab
  SourcePort          : 65502
  DestinationIp       : <WS_PRIVATE_IP>
  DestinationHostname : WS01
  DestinationPort     : 5985                              # WinRM HTTP
```

### Key indicators

- `DestinationPort = 5985` is WinRM HTTP. WinRM HTTPS would be 5986.
- `Initiated = true` confirms outbound direction.
- Combined with Event 4624 Type 3 on the target (showing source IP = `<DC_PRIVATE_IP>`), this gives a full bidirectional chain.
- Inside the PSRemoting session, commands run on the remote machine are captured by Sysmon and PowerShell logging on `ws01`, NOT on `dc01`. Specifically `wsmprovhost.exe` (WS-Management provider host) spawns as the parent of all remote commands.

### Detection logic

```
Detection at origin :
  Event Log : Microsoft-Windows-Sysmon/Operational (source)
  Event ID  : 3
  Conditions :
    Destination_Port = 5985 OR 5986
    AND Direction = "outbound"
    AND Process_Name = "powershell.exe" OR "pwsh.exe"

Detection at target :
  Event Log : Security (destination)
  Event ID  : 4624
  Conditions :
    Logon_Type = 3
    AND Authentication_Package = "Kerberos"
    AND Source_Network_Address NOT IN authorized_admin_workstations
```

---

## Coverage Summary

| Technique             | MITRE      | Primary signal       | Detection rate |
|-----------------------|------------|----------------------|----------------|
| Kerberoasting         | T1558.003  | 4769 (RC4 = 0x17)    | 1 / 1          |
| AS-REP Roasting       | T1558.004  | 4768 (Pre-auth = 0)  | 1 / 1          |
| AD Enumeration        | T1087.002  | 4104 + Sysmon 1      | 1 / 1          |
| LSASS Memory Dump     | T1003.001  | Sysmon 11 (Event 10 filtered) | 1 / 1 |
| PSRemoting lateral    | T1021.006  | Sysmon 3 (port 5985) | 1 / 1          |

All 5 techniques produced detectable artifacts using nothing but Sysmon, PowerShell logging, and native Windows event auditing. No third-party offensive tool involved. The detection chain is purely behavioural.

## See also

- `03-detection-scenarios.md` for the 6 native scenarios
- `05-lessons-learned.md` for the SwiftOnSecurity LSASS whitelist trade-off and the Sysmon network filter limitation
- `06-mitre-mapping.md` for the consolidated ATT&CK table
