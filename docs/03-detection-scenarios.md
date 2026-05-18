# 03. Detection Scenarios (6 native)

Six attack scenarios executed on `dc01` during Day 3, with captured Event Viewer output and a SIEM-agnostic detection rule for each. All outputs are real captures from the lab, anonymized per the rules in `evidence/README.md`. The five bonus Red/Blue techniques are documented separately in `04-redblue-techniques.md`. The full MITRE ATT&CK mapping is in `06-mitre-mapping.md`.

> Formal Sigma rule conversions and SPL / KQL ports are planned for v2 (see `evidence/README.md`).

---

## Scenario 1 : Password Spray (Kerberos + NTLM)

**MITRE :** T1110.003 Brute Force : Password Spraying
**Native + Sysmon coverage :** native only (Security log)

### Story

`net use \\dc01\c$ /user:BECODE\julie.martin WrongPassword!` was repeated 6 times to simulate a low-and-slow password spray against a known account. A second variant used the DC's IP instead of its hostname, which forced an NTLM fallback. Both spray paths were exercised so that detection coverage could be verified across protocols.

### Captured output : Event 4771 (Kerberos failure)

```
Provider    : Microsoft-Windows-Security-Auditing
EventID     : 4771
TimeCreated : 2026-03-23T09:21:09Z
Computer    : dc01.becode.corp.lab

EventData :
  TargetUserName : julie.martin
  TargetSid      : {REDACTED}
  ServiceName    : krbtgt/BECODE
  TicketOptions  : 0x40810010
  Status         : 0x18                  # bad password
  PreAuthType    : 2                     # timestamp pre-auth used
  IpAddress      : ::1                   # loopback, test ran from DC itself
  IpPort         : 0
```

### Captured output : Event 4625 (NTLM failure)

```
EventID        : 4625
TargetUserName : julie.martin
LogonType      : 3                       # network
Status         : 0xC000006D
SubStatus      : 0xC000006A              # wrong password
Authentication : NtLmSsp / NTLM
```

### Key indicators

- `Status 0x18` is the canonical "bad password" Kerberos failure code.
- `PreAuthType = 2` confirms standard pre-auth was attempted (AS-REP would be `0`).
- When sprayed from `ws01`, `Client IP` on Event 4771 becomes `<WS_PRIVATE_IP>` and `Workstation Name` on Event 4625 becomes `WS01`, providing origin tracking.

### Detection logic

```
Event Log : Security (DC)
Event ID  : 4771 OR 4625
Conditions :
  COUNT(failures) BY Account_Name WITHIN 15 minutes
  WHERE COUNT >= 5
  AND (Failure_Code = "0x18"  for 4771
       OR Sub_Status_Code IN ["0xC0000064", "0xC000006A"] for 4625)
```

An attacker who knows that 4625 is the most-watched event can use the hostname form to force Kerberos and trigger only 4771. A SOC rule that only alerts on 4625 misses half the spray. Coverage requires both event IDs together.

---

## Scenario 2 : Backdoor Account Creation

**MITRE :** T1136.001 Create Account : Local Account (mapped to domain account here)
**Native + Sysmon coverage :** native only (Security log)

### Story

A backdoor account `support.helpdesk` was created from an interactive RDP session as `azureadmin`, immediately added to `Domain Admins`, then deleted shortly after to simulate an attacker covering tracks. The three event chain (creation + privilege assignment + deletion) was captured in full.

### Captured output : Event 4720 (account creation)

```
A user account was created.

Subject :
  Security ID  : BECODE\azureadmin
  Account Name : azureadmin
  Logon ID     : {REDACTED}

New Account :
  Security ID    : BECODE\support.helpdesk
  Account Name   : support.helpdesk
  Account Domain : BECODE

Attributes :
  SAM Account Name      : support.helpdesk
  Display Name          : Support Helpdesk
  User Principal Name   : support.helpdesk@becode.corp.lab
  Primary Group ID      : 513                       # Domain Users
  Old UAC Value         : 0x0
  New UAC Value         : 0x15
  User Account Control  :
    Account Disabled                                # initially created disabled
    Password Not Required - Enabled                 # RED FLAG
    Normal Account - Enabled
```

### Captured output : Event 4728 (added to Domain Admins)

```
A member was added to a security-enabled global group.

Subject :
  Account Name : azureadmin
  Logon ID     : {REDACTED}

Member :
  Security ID : BECODE\support.helpdesk
  DN          : CN=Support Helpdesk,CN=Users,DC=becode,DC=corp,DC=lab

Group :
  Group Name   : Domain Admins
  Group Domain : BECODE
```

### Captured output : Event 4726 (cleanup)

```
EventID         : 4726 (account deleted)
Subject Account : azureadmin (Logon ID {REDACTED})
Target Account  :
  Security ID  : {REDACTED}
  Account Name : support.helpdesk
```

### Key indicators

- `Password Not Required - Enabled` in the UAC flags of Event 4720 is highly suspicious by itself. Legitimate provisioning never bypasses password complexity.
- `CN=Users` in the DN of Event 4728 : default container, not a managed OU. A real Tier 0 admin would be provisioned in a dedicated PAM-controlled OU.

### Detection logic

```
Event Log : Security (DC)
Pattern   : sequence within 24 hours

  Event ID = 4720 (account created)
  WHERE Target_DN MATCHES "CN=Users,DC=*"
  AND New_UAC_Value contains "Password Not Required"
THEN
  Event ID = 4728 (added to global security group)
  WHERE Group_Name IN ["Domain Admins", "Enterprise Admins", "Schema Admins"]
```

Fire on the `4720 + 4728` pair within a short window, not on Event 4726 alone. The deletion happens at the end of the attack chain, often hours after the damage is done.

---

## Scenario 3 : DC Reconnaissance

**MITRE :** T1087.002 Account Discovery : Domain Account (partial, plus SYSVOL recon)
**Native + Sysmon coverage :** Sysmon Event 1 carries the value (native 4688 is too thin)

### Story

`repadmin /showrepl` was executed on the DC to simulate reconnaissance of replication partners. SYSVOL browsing was also performed but did not generate a dedicated event by default.

### Captured output : Sysmon Event 1

```
Provider    : Microsoft-Windows-Sysmon
EventID     : 1
TimeCreated : 2026-03-23T09:51:30Z
Computer    : dc01.becode.corp.lab

EventData :
  Image              : C:\Windows\System32\repadmin.exe
  CommandLine        : repadmin /showrepl
  CurrentDirectory   : C:\Users\azureadmin\
  User               : BECODE\azureadmin
  LogonId            : {REDACTED}
  TerminalSessionId  : 2                              # RDP session
  IntegrityLevel     : High
  Hashes             : MD5=0550E2F5EDC7C9717D27997F869160AE
                       SHA256=D49516565B99AE631B1F4B6D5BF9CDE04CE5E299D52C7C84A85B9CAC54F5895D
                       IMPHASH=15495607BE90AA26561E5DC8398D0A3A
  ParentImage        : C:\Windows\System32\cmd.exe
  ParentCommandLine  : "C:\Windows\system32\cmd.exe"
  ParentUser         : BECODE\azureadmin
```

### Key indicators

- Native Event 4688 only shows that `repadmin.exe` was launched. Sysmon Event 1 adds full command line, parent process chain, file hashes (for VirusTotal pivoting), and execution context.
- `repadmin.exe` is Microsoft-signed. Detection cannot rely on signatures, only on behaviour : `repadmin` running outside scheduled maintenance windows, from an interactive RDP session, on a host that is not the admin bastion.

SYSVOL browsing produces no dedicated Event ID by default. File-access auditing on SYSVOL would surface it but is generally too noisy for production. SYSVOL recon remains one of the hardest blue-team coverage gaps.

### Detection logic

```
Event Log : Microsoft-Windows-Sysmon/Operational (DC)
Event ID  : 1
Conditions :
  Image ENDS WITH "\repadmin.exe"
  AND TerminalSessionId > 0                        # interactive RDP session
  AND NOT (User IN approved_replication_admins
           AND CurrentTime IN approved_maintenance_window)
```

---

## Scenario 4 : Encoded PowerShell

**MITRE :** T1027 Obfuscated Files or Information + T1059.001 PowerShell
**Native + Sysmon coverage :** native (Event 4104) is sufficient and decisive

### Story

A reconnaissance command was Base64-encoded, then executed via `powershell.exe -EncodedCommand`. Without ScriptBlock logging, a SOC would see only an opaque blob. With it, the decoded intent is recorded.

### Encoding workflow used

```powershell
$cmd = "Get-LocalUser | Where-Object { $_.Enabled -eq $true }"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host "Encoded: $encoded"
```

Then :

```
powershell.exe -EncodedCommand <base64_string>
```

### Captured output : Event 4104 (decoded)

```
ScriptBlock text (1 of 1) :
Get-LocalUser | Where-Object { .Enabled -eq True }

ScriptBlock ID : {REDACTED}
```

Note : the captured decoded command shows `.Enabled` and `True` instead of `$_.Enabled` and `$true`. The dollar-prefixed PowerShell variables were stripped during `cmd.exe` variable expansion BEFORE the Base64 encoding ran. ScriptBlock logging records whatever PowerShell actually saw, including damaged payloads.

### Key indicators

- Without ScriptBlock logging : SOC sees `powershell.exe -EncodedCommand RwBlAHQALQBMAG8AYwBhAGwAVQBzAGUAcgAg...` in Event 4688 only.
- With ScriptBlock logging : SOC sees the decoded intent.
- GPO must enable ScriptBlock logging domain-wide as a non-negotiable baseline.

### Detection logic

```
Event Log : Microsoft-Windows-PowerShell/Operational
Event ID  : 4104
Conditions :
  Script_Block_Text contains :
    "Invoke-Mimikatz", "DownloadString", "FromBase64String",
    "IEX", "Invoke-Expression"

OR
Event Log : Security
Event ID  : 4688
Conditions :
  Process_Name = "powershell.exe"
  AND Command_Line contains "-EncodedCommand" OR "-enc " OR "-e "
```

---

## Scenario 5 : Scheduled Task Persistence

**MITRE :** T1053.005 Scheduled Task/Job : Scheduled Task
**Native + Sysmon coverage :** native (Event 4698) is the primary signal

### Story

A scheduled task `ServerMaintenanceHelper` was created to simulate persistence. The task name is deliberately benign-sounding, the kind of label an attacker would pick to blend with legitimate maintenance jobs.

### Captured behaviour

Event 4698 fired in the Security log with the task name and the action invoked. Important practical note : when filtering Event 4698 by time window, the first matching event was a legitimate Windows Defender scheduled scan (`\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`), not the test task. Both were created at nearly the same time. Reading the `TaskName` field carefully is essential.

### Key indicators (malicious task)

- TaskName outside the `\Microsoft\Windows\*` namespace
- Trigger set to "At log on" (persistence)
- "Run with highest privileges" enabled
- "Run whether user is logged on or not" enabled
- Action invokes `cmd.exe` or `powershell.exe` with arguments

### Detection logic

```
Event Log : Security
Event ID  : 4698
Conditions :
  TaskName NOT STARTS WITH "\Microsoft\Windows\"
  AND ( Action_Image ENDS WITH "powershell.exe"
        OR Action_Image ENDS WITH "cmd.exe"
        OR Action_Image ENDS WITH ".vbs"
        OR Action_Image ENDS WITH ".js" )
  AND ( Trigger_Type = "AtLogon"
        OR Run_With_Highest_Privileges = TRUE )
```

---

## Scenario 6 : Outbound Connection (C2-style DNS)

**MITRE :** T1071.001 Application Layer Protocol : Web Protocols + T1071.004 DNS
**Native + Sysmon coverage :** Sysmon Event 22 is decisive (no native equivalent)

### Story

First attempt used Edge to navigate to `https://example.com`. Edge produced noisy adjacent DNS queries (`wpad`, `searchapp.bundleassets.example` telemetry) but no clean `example.com` Event 22 surfaced within the test window. The unambiguous trigger came from PowerShell directly.

### Trigger

```powershell
Resolve-DnsName example.com
```

### Captured output : Sysmon Event 22

```
Dns query :
  RuleName     : -
  UtcTime      : 2026-03-23 10:34:54.430
  ProcessId    : 6208
  QueryName    : example.com
  QueryStatus  : 0                                              # success
  QueryResults : 2606:4700::6812:1a78;
                 2606:4700::6812:1b78;
                 ::ffff:104.18.27.120;
                 ::ffff:104.18.26.120;
  Image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  User         : BECODE\azureadmin
```

### Key indicators

- `Image` ties the query to a specific process. C2 beaconing from `notepad.exe` would be obviously anomalous.
- `QueryResults` shows the resolved IPs, here Cloudflare anycast for `example.com`.
- `QueryStatus = 0` means resolution succeeded. Non-zero values often indicate DGA-style failed lookups.

Adjacent finding : when looking for a follow-up Sysmon Event 3 (network connection from PowerShell to those Cloudflare IPs), none appeared. The SwiftOnSecurity config selectively filters PowerShell network connections to reduce noise. Detection of C2 over DNS in this lab relies on Event 22 alone, not the ideal Event 3 + Event 22 correlation.

### Detection logic

```
Event Log : Microsoft-Windows-Sysmon/Operational
Event ID  : 22
Conditions :
  Image IN ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe"]
  AND QueryName NOT IN known_business_domains
```

---

## Coverage Summary

| Scenario | MITRE      | Primary signal     | Detection rate |
|----------|------------|--------------------|----------------|
| 1        | T1110.003  | 4771 + 4625        | 1 / 1          |
| 2        | T1136.001  | 4720 + 4728 + 4726 | 1 / 1          |
| 3        | T1087.002  | Sysmon 1           | 1 / 1          |
| 4        | T1027      | 4104               | 1 / 1          |
| 5        | T1053.005  | 4698               | 1 / 1          |
| 6        | T1071.001  | Sysmon 22          | 1 / 1          |

All 6 scenarios produced detectable artifacts. Coverage of the 5 bonus Red/Blue techniques is in `04-redblue-techniques.md`.
