# 01. Architecture and Threat Model

## 1. Topology

```
                          Internet
                              |
                              | RDP 3389 (exposed by lab requirement)
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
   |                                                      |
   |   Resource group : rg-lab-ad                         |
   |   Region         : Sweden Central                    |
   |   VM size        : B2ls_v2 (dc01) / B2als_v2 (ws01)  |
   |   Auto-shutdown  : 17:00 UTC+1                       |
   +------------------------------------------------------+
```

Lab is hosted entirely in a single Azure VNet. Both VMs sit in the same subnet so that Kerberos, LDAP, DNS and DHCP traffic between dc01 and ws01 never crosses the public internet. The only intentional exposure is RDP 3389 on dc01, accepted to enable BeCode mentor remote review and to surface real-world attack telemetry against an internet-facing DC.

## 2. Lab Quick Reference

**Azure :**

- Resource group : `rg-lab-ad`
- Region : Sweden Central
- VM size DC : Standard_B2ls_v2 (Intel, 2 vCPU, 4 GB RAM)
- VM size client : Standard_B2als_v2 (AMD, 2 vCPU, 8 GB RAM)
- Auto-shutdown : 17:00 UTC+1

**Domain Controller :**

- Forest level : Windows Server 2025
- Domain : `becode.corp.lab`
- NetBIOS : `BECODE`
- DNS zones : `becode.corp.lab` + `_msdcs.becode.corp.lab`
- 5 SRV records
- 16 default security groups + 3 default user accounts + `azureadmin`

**Service accounts (3, all in `OU=ServiceAccounts`) :**

- `svc_backup`
- `svc_ftp`
- `svc_monitor`

**Sysmon :**

- Version 15.15 on both hosts
- Configuration : SwiftOnSecurity `sysmon-config`
- Install date : 23/03/2026

## 3. Design Choices

| Choice                                          | Reason                                                                                                  |
|-------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Single Azure VNet, both VMs in same subnet      | Minimises Kerberos / DNS / DHCP misconfiguration risk for a 3 day exercise.                             |
| Windows Server 2025 for the DC                  | Highest available forest functional level, exposes the latest event schema (e.g. Sysmon 15.15 fields).  |
| Windows 10 Enterprise LTSC for the client       | Matches typical SMB endpoint deployment, stable for repeated detection drills.                         |
| B2ls_v2 (DC) / B2als_v2 (client) sizing         | Azure for Students subscription budget constraint. B2ls_v2 (DC, Intel Xeon, 2 vCPU / 4 GB RAM) and B2als_v2 (client, AMD EPYC, 2 vCPU / 8 GB RAM) were the cheapest burstable v2 sizes available at the time of provisioning. The AMD variant happens to ship with more RAM per vCPU than the Intel equivalent, which is acceptable since the client absorbs the bulkier Windows 10 Enterprise workload. |
| Sweden Central region                           | Low Azure cost tier, no compliance constraint for a lab.                                                |
| Auto-shutdown at 17:00 UTC+1                    | Cost control, mandatory in BeCode lab guidance.                                                         |
| Sysmon on both DC and client                    | Authentication events live on the DC, action events live on the workstation. Both halves needed.       |
| SwiftOnSecurity sysmon-config (out of the box)  | Industry-standard starting point. Documented limitations are noted in `05-lessons-learned.md`.         |
| DC exposed on RDP 3389 (with the caveats below) | BeCode lab requirement + deliberate honeypot effect to observe real-world attack traffic.               |

## 4. Threat Model

The lab is built to simulate and detect a small but representative slice of an enterprise compromise chain. Threats in scope :

| Threat                         | MITRE ATT&CK         | Detection layer                                       |
|--------------------------------|----------------------|-------------------------------------------------------|
| Password spray (Kerberos)      | T1110.003            | DC Security log, Event 4771                           |
| Password spray (NTLM fallback) | T1110.003            | DC Security log, Event 4625                           |
| Backdoor account creation      | T1136.001            | DC Security log, Events 4720 + 4728 + 4726            |
| DC reconnaissance              | T1087.002 (partial)  | DC Sysmon Event 1 (`repadmin`, command line)          |
| Encoded PowerShell             | T1027 + T1059.001    | PowerShell Operational, Event 4104                    |
| Scheduled task persistence     | T1053.005            | DC Security log, Event 4698                           |
| Outbound C2 / DNS exfil        | T1071.001 / T1071.004| DC Sysmon Event 22                                    |
| Kerberoasting                  | T1558.003            | DC Security log, Event 4769 (Ticket Encryption 0x17)  |
| AS-REP Roasting                | T1558.004            | DC Security log, Event 4768 (Pre-Auth Type 0)         |
| LSASS memory dump              | T1003.001            | Sysmon Event 11 (Event 10 filtered by SwiftOnSec)     |
| Lateral movement via PSRemoting| T1021.006            | Source Sysmon Event 3 + target Event 4624 Type 3      |

Out of scope for v1 :

- Cross-forest trust attacks (single domain lab)
- Adversary-in-the-middle (no NTLM relay tooling)
- Ransomware-grade endpoint impact (no EDR to validate against)
- Cloud-side identity attacks (no Entra ID hybrid join)

The 11 in-scope techniques are documented in detail in `03-detection-scenarios.md` (6 native scenarios) and `04-redblue-techniques.md` (5 bonus Red/Blue techniques). The full table with Event IDs and detection coverage status lives in `06-mitre-mapping.md`.

## 5. Trust Boundaries

| Boundary                                    | Control                                                |
|---------------------------------------------|--------------------------------------------------------|
| Internet to RDP on dc01                     | None (deliberate exposure for storytelling section)    |
| Internet to any other port on dc01 or ws01  | Azure NSG default deny inbound                         |
| ws01 to dc01 internal protocols             | VNet-internal, allowed                                 |
| Inside the domain (user > resource)         | AD ACLs + GPOs (Default Domain Policy + Security-Monitoring) |

The single deliberate weakness is RDP 3389 on dc01. This is the only "front door" any external party can knock on, and it is what produced the unsolicited credential stuffing attempts described in `05-lessons-learned.md`.

## 6. What This Architecture Does Not Promise

The lab is not production-grade. It is a single Azure tenant with one DC, no HA, no offsite backups, and a permissive RDP exposure. It is purpose-built to demonstrate the build, harden, and detect workflow on a small footprint, not to model a resilient enterprise. The accepted risks documented in `lab-documentation.md` section 13 make this explicit.
