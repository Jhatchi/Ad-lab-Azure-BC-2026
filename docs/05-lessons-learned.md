# 05. Lessons Learned

What the lab actually taught beyond the scripted scenarios : real-world friction, an unsolicited external attack, and the trade-offs of a default detection configuration.

---

## 1. Real-World Validation : External Attack Observed During Lab

**Date :** 23/03/2026, during the lab's Day 3 monitoring window.

**Context :** the DC was exposed on the internet with port 3389 (RDP) open, per BeCode lab requirement. During Day 3 monitoring, automated authentication attempts started arriving from a public IP unrelated to the lab.

**Source IP :** `185.156.73.74`. External, public, no relation to the lab tenant. Preserved here (and only here, plus the README) as the storytelling asset that justifies the entire monitoring chain.

### Captured output : Event 4625 (one of many)

```
EventID  : 4625 (account failed to log on)
Computer : dc01.becode.corp.lab

Subject :
  Security ID    : NULL SID
  Account Name   : -
  Account Domain : -
  Logon ID       : 0x0

Logon Type : 3 (Network)

Failed Logon Account :
  Security ID    : NULL SID
  Account Name   : empfang                  # not a real account in the lab
  Account Domain : BECODE

Failure Information :
  Failure Reason : Unknown user name or bad password
  Status         : 0xC000006D
  Sub Status     : 0xC0000064               # STATUS_NO_SUCH_USER

Process Information :
  Caller Process ID   : 0x0                 # no local process, pure network connection
  Caller Process Name : -

Network Information :
  Workstation Name       : -                # bot does not advertise a workstation
  Source Network Address : 185.156.73.74    # external attacker
  Source Port            : 0

Detailed Authentication Information :
  Logon Process  : NtLmSsp
  Authentication : NTLM
  Package Name   : -                        # no NTLM v2 hash exchange completed
  Key Length     : 0                        # no session key derived
```

### Pattern observed across multiple successive events

- Same source IP `185.156.73.74`
- Different non-existent usernames tried : `vincent`, `empfang`, `qlik`, and other generic identifiers
- Always `Sub Status 0xC0000064` (user does not exist)
- Always NTLM, never Kerberos (the bot connects by IP, not hostname)
- Always empty `Workstation Name` (bot does not announce itself)
- Always `Caller Process ID 0x0` (pure network authentication, no local process initiation)

### Adjacent Kerberos artifact

During the same monitoring window, an unrelated Event 4768 was also captured with `Account Name : NOUSER`, `User ID : NULL SID`, `Result Code : 0x6` (KDC_ERR_C_PRINCIPAL_UNKNOWN). This pattern is consistent with Kerberos username enumeration tools such as `kerbrute userenum`. The exposed DC was being probed across multiple authentication protocols, not just NTLM.

### What this means in plain language

- A bot scans the public IPv4 range for hosts with RDP exposed.
- It tries a dictionary of common usernames in the hope of stumbling on a real account.
- The usernames (`empfang` is German for "reception", `qlik` is a BI tool product name) suggest a generic credential-stuffing dictionary, not lab-specific reconnaissance.
- The DC was hit BEFORE any real users existed beyond the lab personas, so the attacker had a 100 percent failure rate.
- The exact same pattern, scaled up, is how a portion of real ransomware affiliates compromise enterprise DCs that get accidentally exposed.

### Why this matters for the portfolio

- Empirical evidence that any internet-exposed DC is targeted during its monitoring window. This is not theory, it is a packet capture in disguise.
- Justifies every accepted risk listed in `lab-documentation.md` section 13 (single DC, RDP exposed) with weight beyond theory.
- Validates the entire monitoring chain (audit policy + Security log + detection logic from `03-detection-scenarios.md`) by showing it captures real-world threats out of the box.

### Behavioural detection variant for the external case

```
Event Log : Security (DC)
Event ID  : 4625
Conditions :
  AND Source_Network_Address NOT IN known_internal_subnets
  AND Account_Name NOT IN active_directory_users
  -> immediate alert, no threshold
```

Internal password spray needs a threshold (5 in 15 minutes). External password spray against non-existent accounts is anomalous from the very first event and warrants immediate alerting.

### Threat Intel Corroboration (Open-Source)

Live open-source threat intel investigation of `185.156.73.74`, performed during the lab on 24/03/2026 against the public VirusTotal IP report, and re-verified on 18/05/2026 to confirm the verdict persistence. This step elevates the lab capture from a passive observation to an investigated finding, the posture a junior CTI analyst would take on every interesting external IP that shows up in their logs.

**VirusTotal verdict** :

- Detection score : **7 / 92** security vendors flag the IP as malicious, plus 1 flagging suspicious
- Vendors flagging as malicious : ADMINUSLabs, alphaMountain.ai, Chong Lua Dao, CyRadar, Forcepoint ThreatSeeker, Guardpot, SOCRadar (Malware)
- Vendor flagging as suspicious : AlphaSOC
- Community score : -1
- Last analysis on VirusTotal : 25 days ago at the time of the query

**Network attribution** :

- ASN : AS 211736 (FOP Dmytro Nedilskyi)
- Network name : Reldas-net (`185.156.73.0/24`)
- Registered country : Ukraine (UA) via RIPE NCC
- Maintainer : `ru-ip84-1-mnt`. A Russian-prefixed maintainer handle on a Ukrainian netblock is itself a notable artefact and consistent with the broader pattern of cross-border infrastructure overlap in this region.
- Organisation : ORG-TE87-RIPE (TOV E-RISHENNYA, Kiev, Ukraine)

**Crowdsourced threat intel (Guardpot honeypot network)** :

- Verdict severity : HIGH
- Category : Remote command execution and system compromise
- Total observed events : **286** distinct attack events
- Period observed : 2025-04-18 22:03 UTC to 2025-05-17 21:43 UTC
- Attack type breakdown :
  - `tcp-portscan` : 96 events
  - `smtp-request` : 70 events
  - `ftp-command` : 48 events
  - `imap-request` : 26 events
  - `mysql-login` : 25 events
  - `mssql-login` : 21 events

**Interpretation, what this changes vs the initial lab observation :** the lab captured RDP-targeted credential stuffing only. The wider threat intel confirms that `185.156.73.74` is a multi-protocol scanner and login-probe node hitting at least six distinct service stacks (TCP port reconnaissance, mail SMTP and IMAP, file transfer FTP, databases MySQL and MSSQL). The bot's behaviour against the lab DC is one slice of a broader opportunistic scanning operation, not a targeted attack against this specific lab. This profile fits the textbook description of credential-stuffing infrastructure used by ransomware affiliates and initial-access brokers, exactly the threat model the lab's monitoring chain was built to detect.

Source : VirusTotal IP report at <https://www.virustotal.com/gui/ip-address/185.156.73.74>, queried first during the lab on 24/03/2026 and re-verified on 18/05/2026. The data above reflects the state at the time of the most recent verification. Verdicts may evolve over time ; readers can check the current status at the link above.

---

## 2. SwiftOnSecurity LSASS Whitelist : the LOLBin Trade-Off

SwiftOnSecurity's `sysmon-config` whitelists `Taskmgr.exe` accessing `lsass.exe`. The reasoning is sound : Task Manager opens LSASS handles constantly for legitimate UI reasons, and unfiltered Event 10 noise drowns real attacks. The cost : an attacker who knows the whitelist can use Task Manager itself as an LSASS dumping LOLBin.

The lab confirmed this end to end :

1. Triggered an LSASS dump from Task Manager > Details > right-click `lsass.exe` > Create dump file.
2. Sysmon Event 10 was NOT generated.
3. Sysmon Event 11 (File Create) DID fire on the `lsass.DMP` artifact.

Detection still worked, but only through the file-write fallback. A more aggressive attacker who pipes the dump through a different exfiltration path (in-memory only, no file written to disk) would slip past both Event 10 (whitelisted) and Event 11 (no file artifact).

Production take-away : for Tier 0 hosts (Domain Controllers, ADCS, ADFS), tighten the SwiftOnSecurity rule and treat any Task Manager access on `lsass.exe` as worth alerting. Generic noise filtering is not the right default for systems whose compromise yields domain-wide impact.

---

## 3. Sysmon Network Filter Hides PowerShell Event 3

When validating Scenario 6 (outbound DNS query), the follow-up Sysmon Event 3 (network connection from `powershell.exe` to the Cloudflare anycast IPs returned by `Resolve-DnsName`) never appeared. SwiftOnSecurity selectively filters PowerShell network connections to reduce noise.

Consequence : Scenario 6 relies on Event 22 (DNS query) alone, not on the ideal Event 3 + Event 22 correlation. For C2 detection over DNS this is acceptable. For C2 detection over HTTP / HTTPS from PowerShell, the missing Event 3 is a blind spot. A production deployment hunting PowerShell-based C2 should re-enable Event 3 for `powershell.exe` and `pwsh.exe` even at the cost of noise.

---

## 4. Edge Browser Pollutes the Log

First attempt to trigger Scenario 6 was via Edge navigating to `https://example.com`. Edge generated noisy adjacent DNS queries (`wpad`, `searchapp.bundleassets.example` telemetry) but no clean `example.com` Event 22 within the test window. Switching to `Resolve-DnsName example.com` in PowerShell produced an unambiguous Event 22 immediately.

Lab take-away : browser-based tests pollute the log with telemetry traffic. For detection drills, prefer minimal-noise primitives (PowerShell cmdlets, `curl`).

Production take-away : workstation browser telemetry is a real source of detection noise. Use browser allowlists in detection rules rather than fighting telemetry.

---

## 5. Kerberoasting Without Third-Party Tools

The Kerberoasting proof of concept did NOT use Rubeus, Mimikatz, or any external tool. The trigger was 4 lines of pure PowerShell using built-in .NET assemblies :

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
  -ArgumentList "HTTP/becode-backup.becode.corp.lab"
```

A defender looking only for known offensive tool signatures (Rubeus hash, mimikatz strings) misses this completely. Detection has to be behavioural (Event 4769 with `Ticket Encryption Type = 0x17`), not signature-based.

The same logic applies to AS-REP Roasting (just a normal AS-REQ once pre-auth is disabled), AD Enumeration (built-in `Get-AD*` cmdlets), LSASS dumping (Task Manager as LOLBin), and PSRemoting lateral movement (`Enter-PSSession` is a built-in). Five of five Red/Blue techniques in this lab were executed with built-in Windows tooling. Signature-based detection would catch zero of them.

---

## 6. DC vs Client Log Distribution

Authentication events live on the DC. Action events live on the workstation. This is a hard architectural fact that drives where Sysmon must be deployed.

Concrete example from the lab :

- When `leo.simon` logs into `ws01` via RDP, the DC logs Event 4768 (Kerberos TGT issued, `Client Address` = `ws01`'s IP).
- `ws01` itself logs Event 4624 with Logon Type 10 (`RemoteInteractive`).
- The DC does NOT see Logon Type 10 for `leo.simon`, because the session opens on `ws01`.
- When `leo.simon` runs `net user /domain` or `net group "Domain Admins" /domain` from `ws01`, the DC sees only the LDAP traffic that hits it. `ws01` logs Event 4688 with full command line.

Operational consequence : a SOC that only ingests DC logs is blind to half the attack chain. Sysmon on workstations is non-negotiable. This is exactly why Sysmon was installed on both `dc01` and `ws01` in this lab.

---

## 7. Event 4698 First Hit Was a False Positive

When filtering Event 4698 after creating the malicious `ServerMaintenanceHelper` task (Scenario 5), the first matching event was a legitimate Windows Defender scheduled scan task (`\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`), not the test task. Both were created at nearly the same time.

Lesson : when investigating Event 4698 in real incidents, read the `TaskName` field carefully. Malicious indicators :

- Task created outside of `\Microsoft\Windows\*` namespace
- Trigger set to "At log on" (persistence)
- "Run with highest privileges" enabled
- "Run whether user is logged on or not" enabled
- Action invokes `cmd.exe` or `powershell.exe` with suspicious arguments

A naive detection rule "alert on any new 4698" would have alerted on Defender. A rule that requires `TaskName NOT STARTS WITH "\Microsoft\Windows\"` excludes the Defender false positive without losing coverage on attacker-created tasks.

---

## 8. Accepted Risks Justification

`lab-documentation.md` section 13 lists 8 accepted risks. The point of accepting them is not negligence : it is honest scope-setting for a 3 day single-author lab. Each risk has a documented mitigation path for the production version :

| Risk                              | Why accepted in lab                                                        | What would change in production                                |
|-----------------------------------|----------------------------------------------------------------------------|----------------------------------------------------------------|
| claire.admin in Domain Admins     | BeCode scenario explicitly placed her there                                | Strip Domain Admin, use just-in-time PAM                       |
| svc_* PasswordNeverExpires        | No real service relies on them rotating                                    | Move to gMSA (group Managed Service Accounts)                  |
| Stale accounts in CN=Users        | Default Windows behaviour, no real users moved there                       | Quarterly review + automated move to managed OUs               |
| Single DC                         | Cost and time constraint for a 3 day lab                                   | At least 2 DCs in different Azure zones, RODC in branch sites  |
| DC RDP exposed                    | Deliberate for mentor remote review and storytelling                       | Azure Bastion or VPN gateway only, never direct RDP            |
| Scheduled tasks as persistence    | The lab demonstrates the detection rather than blocking the vector         | Group Policy preventing scheduled task creation by non-admins  |

The 185.156.73.74 storytelling section above is the empirical case for the DC RDP exposed risk. The other 7 risks have similar real-world cases that are out of scope for this writeup.

---

## 9. Behavioural Detection vs Signature Detection

The single biggest take-away from running this lab end to end : **none of the 11 techniques used a signed-offensive-tool signature**. All 11 used legitimate Windows tooling, PowerShell, and built-in `.NET` assemblies. A signature-based detection that blocks `mimikatz.exe` would have produced zero detections in this lab.

What worked instead :

- **Volume thresholds** : N failed auth events in T minutes
- **Encryption type anomalies** : RC4 ticket for a service account that has AES available
- **Protocol anomalies** : Kerberos pre-auth disabled, no NTLM session key derived
- **Path / filename signatures** : `*lsass*.DMP`, `repadmin.exe`
- **Process lineage** : `wsmprovhost.exe` as parent of remote commands
- **Time-of-day anomalies** : `repadmin` during interactive RDP session
- **Behavioural sequences** : 4720 + 4728 within a short window

The patterns matter more than the tools. This is the single most portable insight from the lab : detection engineering is about behaviour, not binaries.
