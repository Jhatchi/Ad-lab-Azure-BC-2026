# Lab Documentation : BeCode Corp.

> Anonymized reference document for the AD lab built and instrumented on Azure during a 3 day BeCode Windows module (BCC-2026, March 2026). All hostnames, private IPs, and public IPs that could identify the lab tenant are placeholdered. The external attacker IP `185.156.73.74` is preserved as the storytelling asset described in `05-lessons-learned.md`.

---

## 1. Azure

| Field          | Value             |
|----------------|-------------------|
| Resource group | rg-lab-ad         |
| Region         | Sweden Central    |
| VM size DC     | Standard_B2s      |
| VM size client | Standard_B2s      |
| Auto-shutdown  | 17:00 UTC+1       |

---

## 2. Domain Controller

| Field              | Value                                   |
|--------------------|-----------------------------------------|
| Hostname           | dc01                                    |
| Private IP         | `<DC_PRIVATE_IP>`                       |
| Public IP          | `<PUBLIC_IP_REDACTED>`                  |
| OS                 | Windows Server 2025                     |
| Role               | Active Directory Domain Controller      |
| Domain             | becode.corp.lab                         |
| NetBIOS name       | BECODE                                  |
| Forest level       | Windows Server 2025                     |
| DNS zones          | becode.corp.lab, _msdcs.becode.corp.lab |
| SRV records        | Present (5 records)                     |
| DSRM password      | stored in password manager              |

---

## 3. Client VM

| Field              | Value                                               |
|--------------------|-----------------------------------------------------|
| Hostname           | ws01                                                |
| OS                 | Windows 10 Enterprise LTSC                          |
| Domain joined      | becode.corp.lab                                     |
| DNS server         | `<DC_PRIVATE_IP>`                                   |
| OU                 | OU=Workstations,OU=Devices,DC=becode,DC=corp,DC=lab |
| Sysmon             | Installed v15.15                                    |

---

## 4. Active Directory Initial State (Day 1)

| Object                | Count / Detail                                                              |
|-----------------------|-----------------------------------------------------------------------------|
| OUs (default)         | 1 (Domain Controllers)                                                      |
| Containers (default)  | 4 (Builtin, Computers, ForeignSecurityPrincipals, Managed Service Accounts) |
| User accounts         | 3 (Administrator, Guest, krbtgt) + azureadmin                               |
| Security groups       | 16 (Domain Admins, Domain Users, Enterprise Admins, Schema Admins, etc.)    |
| Domain Admins members | Administrator, azureadmin                                                   |

---

## 5. DNS Verification

| Check                                 | Result                                                                  |
|---------------------------------------|-------------------------------------------------------------------------|
| Forward zone `becode.corp.lab`        | Present                                                                 |
| `_msdcs.becode.corp.lab` zone         | Present                                                                 |
| Reverse lookup zone                   | Azure managed                                                           |
| SRV records (`_ldap`, etc.)           | OK, 5 records : `_gc`, `_kerberos`, `_ldap` over TCP + `_kerberos`, `_kpasswd` over UDP |
| `nslookup becode.corp.lab`            | OK, resolves to `<DC_PRIVATE_IP>`                                       |
| `nslookup dc01.becode.corp.lab`       | OK, resolves to `<DC_PRIVATE_IP>`                                       |

---

## 6. Kerberos

| Field                | Value                                  |
|----------------------|----------------------------------------|
| TGT issuer           | krbtgt/BECODE.CORP.LAB                 |
| TGT expiry           | 10 hours after issuance (per default)  |
| Default TGT lifetime | 10 hours                               |

---

## 7. Event Log Check (Day 1)

| Log               | Critical errors | Notes                                                                  |
|-------------------|-----------------|------------------------------------------------------------------------|
| Directory Service | 0               | 6 normal post-promotion warnings : IDs 643, 614, 1539, 1463, 3051, 3054 |

---

## 8. BeCode Corp. Active Directory Structure (Day 2)

### 8.1 Departments and OUs

| Department       | OU Path                                                |
|------------------|--------------------------------------------------------|
| Management       | OU=Management,OU=Corp,DC=becode,DC=corp,DC=lab         |
| Study            | OU=Study,OU=Corp,DC=becode,DC=corp,DC=lab              |
| Production       | OU=Production,OU=Corp,DC=becode,DC=corp,DC=lab         |
| Support-A        | OU=Support-A,OU=Support,OU=Corp,DC=becode,DC=corp,DC=lab |
| Support-B        | OU=Support-B,OU=Support,OU=Corp,DC=becode,DC=corp,DC=lab |
| IT               | OU=IT,OU=Corp,DC=becode,DC=corp,DC=lab                 |
| Service Accounts | OU=ServiceAccounts,OU=Corp,DC=becode,DC=corp,DC=lab    |
| Workstations     | OU=Workstations,OU=Devices,DC=becode,DC=corp,DC=lab    |
| Servers          | OU=Servers,OU=Devices,DC=becode,DC=corp,DC=lab         |

### 8.2 Users (13)

| Username       | Department      | Role                  | Notes                          |
|----------------|-----------------|-----------------------|--------------------------------|
| claire.dupont  | Management      | General Manager       | Admin account : claire.admin   |
| marc.leroy     | Management      | Secretary             |                                |
| thomas.renard  | Study           | Lead Analyst          |                                |
| sophie.lambert | Study           | Researcher            |                                |
| julie.martin   | Production      | Production Supervisor |                                |
| kevin.bernard  | Production      | Operator              |                                |
| leo.simon      | Support-A       | Support Agent         | Member of GRP-Helpdesk         |
| maya.cohen     | Support-B       | Support Agent         |                                |
| alice.sysadmin | IT              | System Administrator  | Domain Admin                   |
| claire.admin   | IT              | Manager admin account | Domain Admin                   |
| svc_backup     | ServiceAccounts | Backup service        | PasswordNeverExpires           |
| svc_ftp        | ServiceAccounts | FTP server            | PasswordNeverExpires           |
| svc_monitor    | ServiceAccounts | Monitoring            | PasswordNeverExpires           |

### 8.3 Security Groups (8)

| Group          | Members                                              |
|----------------|------------------------------------------------------|
| Domain Admins  | Administrator, claire.admin, alice.sysadmin         |
| GRP-Management | claire.dupont, marc.leroy                            |
| GRP-Study      | thomas.renard, sophie.lambert                        |
| GRP-Production | julie.martin, kevin.bernard                          |
| GRP-Support    | leo.simon, maya.cohen                                |
| GRP-IT-Admins  | alice.sysadmin                                       |
| GRP-Corp-All   | GRP-Management, GRP-Study, GRP-Production, GRP-Support |
| GRP-Helpdesk   | alice.sysadmin, leo.simon                            |

---

## 9. DHCP

| Field               | Value                       |
|---------------------|-----------------------------|
| DHCP Server         | dc01.becode.corp.lab        |
| Scope name          | BeCode-Corp-Lab             |
| IP range            | `<DHCP_SCOPE>`              |
| Subnet mask         | 255.255.255.0               |
| Default gateway     | `<DC_PRIVATE_IP>`           |
| DNS server          | `<DC_PRIVATE_IP>`           |
| DNS domain          | becode.corp.lab             |
| Dynamic DNS updates | Enabled                     |

---

## 10. Security Baseline

### 10.1 Password Policy (Default Domain Policy)

| Setting                 | Value         |
|-------------------------|---------------|
| Minimum password length | 12 characters |
| Complexity required     | Enabled       |
| Maximum password age    | 90 days       |
| Minimum password age    | 1 day         |
| Password history        | 10 passwords  |

### 10.2 Account Lockout Policy

| Setting             | Value         |
|---------------------|---------------|
| Lockout threshold   | 5 attempts    |
| Lockout duration    | 15 minutes    |
| Reset counter after | 15 minutes    |

### 10.3 Monitoring (GPO `Security-Monitoring`)

| Setting                          | Status                |
|----------------------------------|-----------------------|
| PowerShell ScriptBlock Logging   | Enabled               |
| PowerShell Module Logging        | Enabled               |
| Audit Kerberos Authentication    | Success + Failure     |
| Audit Logon/Logoff               | Success + Failure     |
| Audit Account Management         | Success + Failure     |
| Audit Process Creation (4688)    | Success               |
| Full command line in 4688        | Enabled               |
| Other Object Access Events       | Success               |

---

## 11. Monitoring Stack (Day 3)

| Control                          | Status    | Log location                                                        |
|----------------------------------|-----------|---------------------------------------------------------------------|
| Process creation auditing (4688) | Enabled   | Windows Logs > Security                                             |
| Full command line in 4688        | Enabled   | Windows Logs > Security                                             |
| PowerShell ScriptBlock logging   | Enabled   | Apps & Services > Microsoft > Windows > PowerShell > Operational    |
| PowerShell Module logging        | Enabled   | Apps & Services > Microsoft > Windows > PowerShell > Operational    |
| Sysmon on dc01                   | Installed | Apps & Services > Microsoft > Windows > Sysmon > Operational        |
| Sysmon on ws01                   | Installed | Apps & Services > Microsoft > Windows > Sysmon > Operational        |

### 11.1 Sysmon

| Field         | dc01                                 | ws01                                 |
|---------------|--------------------------------------|--------------------------------------|
| Version       | 15.15                                | 15.15                                |
| Configuration | SwiftOnSecurity sysmon-config        | SwiftOnSecurity sysmon-config        |
| Log channel   | Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon/Operational |
| Install date  | 23/03/2026                           | 23/03/2026                           |

### 11.2 What each control covers

| Control            | What it detects                                      | What it misses without Sysmon                       |
|--------------------|------------------------------------------------------|-----------------------------------------------------|
| Event ID 4688      | Process creation, executable name, user              | Hash, parent command line, network connections      |
| Event ID 4104      | Every PowerShell command, decoded                    | Nothing (ScriptBlock defeats Base64 obfuscation)    |
| Sysmon Event ID 1  | Full process creation with hash, parent, cmdline     | N/A                                                 |
| Sysmon Event ID 3  | Network connections from every process               | Native Windows logging does not capture this        |
| Sysmon Event ID 22 | DNS queries by process                               | Native Windows logging does not capture this        |

---

## 12. Detection Verification Summary

See `03-detection-scenarios.md` for the 6 native scenarios and `04-redblue-techniques.md` for the 5 bonus Red/Blue techniques. Each scenario is documented with the captured Event Viewer output, a MITRE ATT&CK mapping, and a SIEM-agnostic detection rule.

| Scope                  | Scenarios | Detection rate |
|------------------------|-----------|----------------|
| Day 3 native           | 6         | 6 / 6          |
| Day 3 cross-host (ws01)| 2         | 2 / 2          |
| Bonus Red/Blue         | 5         | 5 / 5          |
| External (unsolicited) | 1         | 1 / 1          |

---

## 13. Known and Accepted Risks

| Risk                              | Who it affects        | Severity | Notes                                                                                        |
|-----------------------------------|-----------------------|----------|----------------------------------------------------------------------------------------------|
| claire.admin in Domain Admins     | Entire domain         | High     | General Manager holds Domain Admin rights. Compromise = full domain takeover. Org decision.  |
| svc_backup PasswordNeverExpires   | Backup data           | Medium   | Password does not rotate. Quarterly manual rotation scheduled.                               |
| svc_ftp PasswordNeverExpires      | FTP storage           | Medium   | Same as above. FTP was publicly accessible in adjacent network project.                      |
| svc_monitor PasswordNeverExpires  | Monitoring logs       | Low      | Read-only monitoring account.                                                                |
| Stale accounts in CN=Users        | Domain authentication | Medium   | Default container cannot receive GPOs. Periodic review recommended.                          |
| Single DC, no redundancy          | Entire domain         | High     | If dc01 goes offline, all authentication fails. Accepted in lab.                             |
| DC exposed on internet (RDP 3389) | Entire domain         | High     | Port 3389 open = immediate target. Lab necessity. Production must require VPN.               |
| Scheduled tasks as persistence    | Entire domain         | Medium   | Tasks created with `Run with highest privileges` at unusual times = attack indicator.        |
