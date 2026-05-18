# 02. Build Walkthrough

Three day timeline of the lab construction, from a blank Azure resource group to a fully instrumented detection environment. The point is not to walk through every click but to document the design decisions and the friction encountered, so a reader can rebuild this lab without repeating the same surprises.

---

## Day 1 : Domain Controller Build

### Goals

1. Provision two Azure VMs (`dc01`, `ws01`) in a single VNet.
2. Promote `dc01` to a Windows Server 2025 forest at functional level WS 2025.
3. Verify DNS, Kerberos, and event log baseline before adding anything else.

### Forest creation

Forest functional level was deliberately set to **Windows Server 2025**, the highest available, to expose the latest schema attributes and Sysmon 15.15 field set. Domain : `becode.corp.lab`, NetBIOS : `BECODE`.

### DNS verification

After promotion, the following checks all returned the expected results :

```
Forward zone becode.corp.lab           : Present
_msdcs.becode.corp.lab zone            : Present
SRV records (_gc, _kerberos, _ldap, _kpasswd) : 5 records, OK
nslookup becode.corp.lab               : OK, resolves to <DC_PRIVATE_IP>
nslookup dc01.becode.corp.lab          : OK, resolves to <DC_PRIVATE_IP>
```

### Kerberos sanity check

`klist` on `dc01` after first interactive login showed :

- TGT issuer : `krbtgt/BECODE.CORP.LAB`
- Default TGT lifetime : 10 hours (per default policy)

### Event log baseline

Directory Service log : **0 critical errors**, 6 normal post-promotion warnings with IDs `643, 614, 1539, 1463, 3051, 3054`. These are expected after a fresh promotion and are documented as benign noise.

---

## Day 2 : Organisational Structure and Hardening

### Goals

1. Build the BeCode Corp. AD structure : 9 OUs, 13 users, 8 security groups.
2. Apply a hardened password and lockout policy via the Default Domain Policy.
3. Deploy a `Security-Monitoring` GPO for auditing and PowerShell logging.
4. Stand up DHCP scope for the workstation subnet.

### OU layout

| Department       | OU Path                                                |
|------------------|--------------------------------------------------------|
| Management       | `OU=Management,OU=Corp,DC=becode,DC=corp,DC=lab`       |
| Study            | `OU=Study,OU=Corp,...`                                 |
| Production       | `OU=Production,OU=Corp,...`                            |
| Support-A        | `OU=Support-A,OU=Support,OU=Corp,...`                  |
| Support-B        | `OU=Support-B,OU=Support,OU=Corp,...`                  |
| IT               | `OU=IT,OU=Corp,...`                                    |
| Service Accounts | `OU=ServiceAccounts,OU=Corp,...`                       |
| Workstations     | `OU=Workstations,OU=Devices,...`                       |
| Servers          | `OU=Servers,OU=Devices,...`                            |

### Users and groups

13 user accounts including 3 dedicated service accounts (`svc_backup`, `svc_ftp`, `svc_monitor`, all with `PasswordNeverExpires`) and 2 Tier 0 admin accounts (`alice.sysadmin`, `claire.admin`). Full table in `lab-documentation.md` section 8.

Eight security groups, including a nested rollup (`GRP-Corp-All`) and a least-privilege helpdesk group (`GRP-Helpdesk`) that allows `leo.simon` to reset passwords without holding Domain Admin.

### Password and lockout policy

Default Domain Policy hardened to :

- Minimum length : 12 characters
- Complexity : enabled
- Maximum age : 90 days
- Minimum age : 1 day (prevents instant rotation back to the old password)
- History : 10 passwords
- Lockout : 5 attempts, 15 minute lockout, 15 minute reset counter

### Security-Monitoring GPO

A dedicated GPO covering everything the BeCode brief asked for and a bit more :

| Setting                          | Status            |
|----------------------------------|-------------------|
| PowerShell ScriptBlock Logging   | Enabled           |
| PowerShell Module Logging        | Enabled           |
| Audit Kerberos Authentication    | Success + Failure |
| Audit Logon/Logoff               | Success + Failure |
| Audit Account Management         | Success + Failure |
| Audit Process Creation (4688)    | Success           |
| Full command line in 4688        | Enabled           |
| Other Object Access Events       | Success           |

> **Aside : pre-authentication option in `dsa.msc` is well hidden.**
> The toggle for AS-REP Roasting setup, "Do not require Kerberos preauthentication", lives inside user Properties > Account tab, in the "Account options" scrolling list, roughly halfway down. Easy to miss when first navigating ADUC. Documented here so the next person rebuilding this lab does not lose 10 minutes hunting for it.

### DHCP scope

DHCP role installed on dc01. Single scope `BeCode-Corp-Lab` covering the workstation range, with the DC's static IP deliberately excluded to avoid IP conflicts. Dynamic DNS updates enabled.

---

## Day 3 : Instrumentation and Detection Drills

### Goals

1. Install Sysmon 15.15 on both `dc01` and `ws01` with SwiftOnSecurity config.
2. Validate that `Audit Process Creation` is producing Event 4688 with full command line.
3. Run 6 native detection scenarios on `dc01`.
4. Run 2 cross-host detection scenarios from `ws01` against `dc01`.
5. Run 5 Red/Blue bonus techniques (Kerberoasting, AS-REP Roasting, AD Enumeration, LSASS Dump, Lateral Movement via PSRemoting).

### Sysmon install

```
Version       : 15.15
Configuration : SwiftOnSecurity sysmon-config
Log channel   : Microsoft-Windows-Sysmon/Operational
Install date  : 23/03/2026 (both hosts)
```

Both VMs installed within minutes of each other to keep Event ID timeline comparable.

### Native vs Sysmon coverage

| Control            | What it adds beyond native logging                        |
|--------------------|-----------------------------------------------------------|
| Sysmon Event ID 1  | Full process creation : hashes, parent process, full cmdline. Equivalent to Event 4688 + missing context. |
| Sysmon Event ID 3  | Network connection by process. No native equivalent.      |
| Sysmon Event ID 11 | File creation. Critical for LSASS dump detection.         |
| Sysmon Event ID 22 | DNS query by process. No native equivalent.               |
| Event 4104         | PowerShell ScriptBlock, decoded. Defeats Base64 obfuscation. |

### Detection drills

Full writeups with captured Event Viewer outputs and the detection event mapping :

- 6 native scenarios : see `03-detection-scenarios.md`
- 5 Red/Blue bonus techniques : see `04-redblue-techniques.md`

### Cross-host drills from ws01

Two attacks were launched from `ws01` to confirm that the DC captures the lateral origin :

1. Kerberos spray via hostname : `net use \\dc01\C$ /user:BECODE\claire.dupont WrongPassword!`. DC logged Event 4771 with `Client IP = <WS_PRIVATE_IP>`.
2. NTLM spray via IP : `net use \\<DC_PRIVATE_IP>\C$ /user:BECODE\claire.dupont WrongPassword!`. DC logged Event 4625 with `Workstation Name = WS01`.

This confirms a hard SOC architecture point : an attacker who knows that Event 4625 is the most-watched event can use the hostname form to force Kerberos and trigger only Event 4771. A SOC that only alerts on 4625 misses half the spray traffic. Both event IDs must be monitored together.

> **Aside : 4768 timing for leo.simon was confusing.**
> Searching for the Event 4768 corresponding to leo.simon's initial RDP login from `ws01` did not surface immediately under the expected filter. The events for `net user /domain` and `net group /domain` do not create Event 4768, because those commands use LDAP, not Kerberos directly. The actual 4768 is generated only at the moment of leo.simon's interactive Kerberos authentication when first opening the RDP session on ws01. Map each event to the protocol that triggered it, not to the action that looks like auth.

> **Aside : encoded PowerShell payload lost syntax through `cmd.exe`.**
> When generating a Base64 payload from `cmd.exe`, dollar-prefixed PowerShell variables (`$_`, `$true`) were stripped before encoding because cmd interpreted them as variable substitutions. The decoded payload visible in Event 4104 was syntactically broken (`.Enabled` instead of `$_.Enabled`) but still partially executed. Real attacker payloads sometimes arrive damaged through transit layers but still cause harm. ScriptBlock logging captures whatever PowerShell actually saw, including damaged payloads.

---

## Operational Notes

### NLA bypass for leo.simon first login

Azure VMs ship with NLA enabled by default on RDP. NLA authenticates BEFORE the desktop session opens, which breaks the "User must change password at next logon" flow on first login. Workaround applied via Azure Run Command (no RDP needed) :

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0
Restart-Service TermService -Force
```

After password change, NLA was restored : `SecurityLayer = 2`, `UserAuthentication = 1`. Leaving NLA off permanently exposes the workstation to fake-login-screen attacks, so the bypass was always treated as temporary.

### PSRemoting setup was not trivial

Initial attempt to enable PSRemoting on `ws01` remotely from the DC via `Invoke-Command` failed with `CannotConnect`. WinRM was not configured to accept inbound connections by default. The setup had to be run directly on `ws01` via RDP :

```powershell
winrm quickconfig -force
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM
```

Production note : `TrustedHosts = "*"` is too permissive. Real environments restrict to a specific list of management hosts. Acceptable in a lab where the only candidate management host is `dc01` itself.

---

## What This Walkthrough Does Not Cover

- Step-by-step Azure portal screenshots : intentionally omitted, the design choices matter more than the click path.
- Sysmon configuration file content : the SwiftOnSecurity config is public, link in `04-redblue-techniques.md`.
- GPO XML exports : will be added under `evidence/gpo-reports/` in v2, see `evidence/README.md`.
