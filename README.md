# AD Lab Azure : Build, Harden, Detect

> Three day BeCode lab (BCC-2026, March 2026) building an Active Directory domain on Azure, hardening it with group policy, instrumenting it with Sysmon and PowerShell logging, and running 11 attack techniques to validate the detection chain end to end. One of the 11 techniques was unsolicited : an external bot started credential-stuffing the DC during the monitoring window. That capture is the centrepiece of section "Notable findings" below.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![markdownlint](https://github.com/Jhatchi/Ad-lab-Azure-BC-2026/actions/workflows/markdownlint.yml/badge.svg)](.github/workflows/markdownlint.yml)
![Status](https://img.shields.io/badge/status-v1.0-blue)

---

## Operational notice

This lab is isolated inside an Azure tenant owned by the author. All attacks documented here were executed on infrastructure the author controls, with all costs and risk borne by the author. The captured external attack from `185.156.73.74` is an unsolicited intrusion attempt against an internet-exposed Domain Controller, observed and logged passively, not provoked or replied to.

The detection techniques described in this repository are intended for defensive use on systems the reader owns or has written authorisation to test. Reproducing the offensive triggers on systems you do not own is unauthorised. The author and BeCode are not responsible for misuse.

---

## TL;DR

- Built a Windows Server 2025 AD domain on Azure from scratch, including OU layout, password policy hardening, group policy auditing, DHCP, and a domain-joined Windows 10 client.
- Instrumented both hosts with Sysmon 15.15 (SwiftOnSecurity config) and PowerShell ScriptBlock logging.
- Ran 6 native attack scenarios + 5 Red/Blue purple-team techniques covering 11 MITRE ATT&CK techniques across 6 tactics. **Detection rate : 11 / 11.**
- Observed an unsolicited external credential-stuffing attack from `185.156.73.74` against the exposed DC during the lab's monitoring window. Captured the full Event 4625 chain and used it as real-world validation of the detection stack.
- Captured 11 Event Viewer detection events end-to-end across the 11 MITRE techniques exercised in the lab.

---

## What this lab demonstrates

| Metric                                   | Count |
|------------------------------------------|-------|
| Active Directory user accounts created   | 13    |
| Security groups designed                 | 8     |
| Organisational Units                     | 9     |
| Native detection scenarios               | 6     |
| Red/Blue bonus techniques                | 5     |
| MITRE ATT&CK techniques mapped           | 11    |
| Captured Event Viewer outputs (verbatim) | 11    |
| Native detection events documented       | 11    |
| Sysmon installations (DC + client)       | 2     |
| Real-world external attacks observed     | 1     |
| Accepted risks documented and justified  | 8     |

---

## Tools used

- **Azure** (Sweden Central, single VNet, Standard_B2ls_v2 (DC) and Standard_B2als_v2 (client) VMs)
- **Windows Server 2025** for `dc01` (AD DS, DNS, DHCP, forest functional level WS 2025)
- **Windows 10 Enterprise LTSC** for `ws01`
- **Sysmon v15.15** with the SwiftOnSecurity `sysmon-config` baseline
- **Event Viewer** for native log inspection (Security, PowerShell Operational, Sysmon Operational)
- **PowerShell** for build automation, hunting queries, and attack triggers
- **GPMC + ADUC** for group policy and directory administration
- **MITRE ATT&CK framework** for technique mapping

---

## How to read this lab

**If you have 30 seconds (recruiter or hiring manager) :** read sections "TL;DR", "Attack and detection coverage", and "Notable findings" below. That covers the what, the how much, and the differentiator.

**If you have 5 minutes (senior analyst doing a first pass) :** add `docs/03-detection-scenarios.md` and `docs/04-redblue-techniques.md`. Each scenario has the captured Event Viewer output and the detection logic in one place.

**If you have 30 minutes (peer or interviewer doing a deep read) :** start with `docs/01-architecture.md` for the threat model, then `docs/02-build-walkthrough.md` for the build decisions, then the two scenario files, then close with `docs/05-lessons-learned.md` for the real-world friction and the external attack writeup.

---

## Architecture at a glance

```
                          Internet
                              |
                              | RDP 3389 (deliberate exposure, see Operational notice)
                              v
   +------------------------------------------------------+
   |              Azure VNet <LAB_SUBNET>                 |
   |                                                      |
   |   +----------------------+   +-------------------+   |
   |   |   dc01               |   |   ws01            |   |
   |   |   <DC_PRIVATE_IP>    |   |   <WS_PRIVATE_IP> |   |
   |   |   WS 2025            |   |   Win10 LTSC      |   |
   |   |   AD DS, DNS, DHCP   |   |   domain-joined   |   |
   |   |   Sysmon 15.15       |   |   Sysmon 15.15    |   |
   |   +----------+-----------+   +---------+---------+   |
   |              |                         |             |
   |              +---- Kerberos, LDAP -----+             |
   |              +---- WinRM (5985/5986) --+             |
   +------------------------------------------------------+
```

Full design rationale and threat model in [`docs/01-architecture.md`](docs/01-architecture.md).

---

## Build summary

**Day 1 :** Provisioned both VMs in a single Azure VNet, promoted `dc01` to a Windows Server 2025 forest, verified DNS (5 SRV records present, forward and reverse zones resolving), confirmed Kerberos TGT issuance, and audited the Directory Service log (0 critical errors, 6 expected post-promotion warnings).

**Day 2 :** Built the BeCode Corp. directory structure (9 OUs, 13 users, 8 security groups), hardened the Default Domain Policy (12-character minimum passwords, complexity required, 90 day max age, account lockout at 5 attempts), and applied a dedicated `Security-Monitoring` GPO covering PowerShell ScriptBlock logging, Kerberos audit, logon/logoff audit, account management audit, and process creation auditing with full command line. Stood up DHCP on the workstation subnet.

**Day 3 :** Installed Sysmon 15.15 on both hosts. Ran 6 native attack scenarios on `dc01` (password spray Kerberos + NTLM, backdoor account creation, DC reconnaissance, encoded PowerShell, scheduled task persistence, outbound DNS query). Ran 2 cross-host scenarios from `ws01` (Kerberos spray via hostname, NTLM spray via IP). Closed with 5 Red/Blue bonus techniques (Kerberoasting, AS-REP Roasting, AD Enumeration via PowerShell, LSASS memory dump, lateral movement via PSRemoting). **All 11 techniques produced detectable events.**

Full walkthrough with operational notes (NLA bypass, PSRemoting prep, encoding damage through cmd.exe) : [`docs/02-build-walkthrough.md`](docs/02-build-walkthrough.md).

---

## Attack and detection coverage

| #  | MITRE ID    | Technique                          | Tactic              | Event ID(s)            | Native | Sysmon | Detected |
|----|-------------|------------------------------------|---------------------|------------------------|--------|--------|----------|
| 1  | T1110.003   | Password Spraying (Kerberos)       | Credential Access   | 4771                   | Full   | N/A    | Yes      |
| 2  | T1110.003   | Password Spraying (NTLM)           | Credential Access   | 4625                   | Full   | N/A    | Yes      |
| 3  | T1136.001   | Create Account (backdoor)          | Persistence         | 4720 + 4728 + 4726     | Full   | N/A    | Yes      |
| 4  | T1087.002   | Account Discovery (Domain)         | Discovery           | 4104, Sysmon 1         | Partial| Full   | Yes      |
| 5  | T1027       | Obfuscated Files (encoded PS)      | Defense Evasion     | 4104, 4688             | Full*  | Bonus  | Yes      |
| 6  | T1053.005   | Scheduled Task persistence         | Persistence         | 4698                   | Full   | Bonus  | Yes      |
| 7  | T1071.001/.004 | Application Layer Protocol      | Command and Control | Sysmon 22              | None   | Full   | Yes      |
| 8  | T1558.003   | Kerberoasting                      | Credential Access   | 4769 (RC4 = 0x17)      | Full   | N/A    | Yes      |
| 9  | T1558.004   | AS-REP Roasting                    | Credential Access   | 4768 (Pre-auth = 0)    | Full   | N/A    | Yes      |
| 10 | T1003.001   | OS Credential Dumping : LSASS      | Credential Access   | Sysmon 11 (10 filtered)| None   | Partial| Yes      |
| 11 | T1021.006   | Remote Services : WinRM (PSRemote) | Lateral Movement    | Sysmon 3, 4624         | Partial| Full   | Yes      |

\* With ScriptBlock logging enabled, which is the GPO baseline applied in this lab.

**Detection rate : 11 / 11.** Full table with detection-rule logic per technique : [`docs/06-mitre-mapping.md`](docs/06-mitre-mapping.md).

Sample captured Event Viewer output (Kerberoasting Event 4769, decisive signal `Ticket Encryption Type = 0x17`) :

```
EventID : 4769 (Kerberos service ticket requested)

Service Information :
  Service Name   : svc_backup
  Available Keys : RC4, AES128-SHA96, AES256-SHA96, AES128-SHA256, AES256-SHA384

Additional Information :
  Ticket Encryption Type : 0x17    # RC4-HMAC (Kerberoasting indicator)
  Failure Code           : 0x0     # success, ticket issued
```

The service account had AES256 available but the attacker tool deliberately requested RC4, the canonical Kerberoasting tell. Full writeup including the pure-PowerShell trigger that did this without Mimikatz or Rubeus : [`docs/04-redblue-techniques.md`](docs/04-redblue-techniques.md).

---

## Notable findings

### Real-world validation : external attack observed during the lab

The DC was internet-exposed on RDP 3389 by lab requirement. During the Day 3 monitoring window, automated authentication attempts started arriving from `185.156.73.74`, an external IP unrelated to the lab. The DC logged them, and the captured Event 4625 chain is the most distinctive evidence in this repository :

```
EventID  : 4625
Computer : dc01.becode.corp.lab
Logon Type : 3 (Network)

Failed Logon Account :
  Account Name : empfang          # not a real account in the lab
  Account Domain : BECODE

Failure Information :
  Sub Status : 0xC0000064          # STATUS_NO_SUCH_USER

Network Information :
  Source Network Address : 185.156.73.74
```

Pattern observed across multiple successive events :

- Different non-existent usernames tried in sequence (`vincent`, `empfang`, `qlik`, etc.) suggesting a generic credential-stuffing dictionary
- Always NTLM (the bot connected by IP, never by hostname)
- Always empty `Workstation Name` (bot does not announce itself)
- Always `Caller Process ID 0x0` (pure network authentication)
- Adjacent Kerberos `4768` events with `Account Name : NOUSER, Result Code : 0x6` consistent with `kerbrute userenum`

This is empirical evidence that any internet-exposed DC is targeted within its monitoring window. It justifies every accepted risk in the documentation with real weight, and it validates the entire monitoring chain end to end against unsolicited real traffic.

Open-source threat intel corroboration on the source IP : 7 / 92 vendors flag it malicious, 286 documented attack events across 6 protocols (port scan, MSSQL / MySQL / FTP / IMAP / SMTP). See [`docs/05-lessons-learned.md`](docs/05-lessons-learned.md) for the full intel block.

Dedicated writeup : [`docs/05-lessons-learned.md`](docs/05-lessons-learned.md) section 1.

### Other take-aways

- **Signature-based detection caught zero of the 11 techniques.** None of them used a known-offensive-tool binary. All used legitimate Windows tooling, PowerShell, or built-in `.NET` assemblies. Detection was 100 percent behavioural : encryption type anomalies, protocol flags, process lineage, filename patterns, volume thresholds.
- **DC logs alone miss half the attack chain.** Authentication events live on the DC, action events live on the workstation. Sysmon on workstations is non-negotiable.
- **The SwiftOnSecurity LSASS whitelist is a real LOLBin trade-off.** Task Manager can dump LSASS without triggering Sysmon Event 10. Event 11 fallback worked, but a more sophisticated attacker would slip past both.

Full lessons-learned writeup : [`docs/05-lessons-learned.md`](docs/05-lessons-learned.md).

---

## Repository structure

```
Ad-lab-Azure-BC-2026/
|-- README.md                          # this file
|-- LICENSE                            # MIT
|-- .gitignore                         # protects raw/, evidence brute, OS junk
|-- .github/workflows/markdownlint.yml # Markdown lint on push and PR
|-- docs/
|   |-- lab-documentation.md           # anonymized reference, every table from the lab
|   |-- 01-architecture.md             # topology, design choices, threat model
|   |-- 02-build-walkthrough.md        # Day 1 + Day 2 + Day 3 writeup with operational notes
|   |-- 03-detection-scenarios.md      # 6 native scenarios, verbatim events + detection rules
|   |-- 04-redblue-techniques.md       # 5 Red/Blue bonus techniques, full workflows
|   |-- 05-lessons-learned.md          # 185.156.73.74 storytelling + 8 other insights
|   `-- 06-mitre-mapping.md            # consolidated MITRE ATT&CK table, 11 techniques
|-- scripts/
|   `-- powershell-snippets.md         # reusable build + hunting + trigger commands
`-- evidence/
    `-- README.md                      # v1 methodology + v2 roadmap (screenshots, GPO exports)
```

---

## Roadmap

### v1.0 (this release)

- [x] Textual lab documentation (`docs/lab-documentation.md`)
- [x] Architecture and threat model (`docs/01-architecture.md`)
- [x] 3 day build walkthrough with operational notes (`docs/02-build-walkthrough.md`)
- [x] 6 native detection scenarios with captured events (`docs/03-detection-scenarios.md`)
- [x] 5 Red/Blue bonus techniques with full workflows (`docs/04-redblue-techniques.md`)
- [x] Lessons learned including external attack writeup (`docs/05-lessons-learned.md`)
- [x] MITRE ATT&CK consolidated mapping (`docs/06-mitre-mapping.md`)
- [x] Reusable PowerShell snippets (`scripts/powershell-snippets.md`)

### v2.0 (separate session, after VM restart)

- [ ] Event Viewer screenshots for the 5 most distinctive captures (`evidence/screenshots/`)
- [ ] GPO HTML exports : Default Domain Policy + Security-Monitoring (`evidence/gpo-reports/`)
- [ ] Live detection demo (GIF or video walkthrough)

Full v2 plan and per-artifact justification in [`evidence/README.md`](evidence/README.md).

---

## License

MIT. See [LICENSE](LICENSE).

## Author

Johan-Emmanuel Hatchi. BeCode Brussels, Cybersecurity track 2026. Connect on [LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/).

Permission to publish this BeCode lab : Thomas Bataboudila, 17 May 2026, general portfolio authorisation for all BeCode projects.
