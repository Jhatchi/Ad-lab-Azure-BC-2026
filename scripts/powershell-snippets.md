# PowerShell Snippets

Reusable commands distilled from the lab. Grouped by purpose. All snippets ran in the lab as documented in `docs/02-build-walkthrough.md`, `docs/03-detection-scenarios.md`, and `docs/04-redblue-techniques.md`.

> Operational notice : run these on systems you own or have written authorisation to test against. See `README.md` Operational notice section.

---

## 1. Lab build helpers

### 1.1 NLA bypass for first interactive password change

Workaround for Azure VMs that ship with NLA enabled. Required to let a domain user complete a "User must change password at next logon" flow over RDP. Run on the workstation via Azure Run Command (no RDP needed).

```powershell
# Disable NLA temporarily
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'SecurityLayer' -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'UserAuthentication' -Value 0
Restart-Service TermService -Force
```

After password change, restore :

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'SecurityLayer' -Value 2
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'UserAuthentication' -Value 1
Restart-Service TermService -Force
```

### 1.2 PSRemoting prep on the target host

Run directly on the workstation, not remotely, because WinRM is not configured to accept inbound by default.

```powershell
winrm quickconfig -force
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM
```

Production note : restrict `TrustedHosts` to a specific list of management hosts, never leave `"*"`.

---

## 2. Detection / hunting queries

### 2.1 Kerberoastable accounts inventory

Spot accounts with a SPN before they get attacked.

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
  -Properties ServicePrincipalName, PasswordLastSet |
  Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet
```

Run as a scheduled daily hunt. Any non-`krbtgt` account with a SPN is a Kerberoasting candidate.

### 2.2 AS-REP Roastable accounts inventory

Spot accounts with Kerberos pre-auth disabled before they get attacked.

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
  -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName
```

Any non-empty result is an immediate finding. Schedule daily.

---

## 3. Red/Blue technique triggers

These are the exact commands used in the lab to produce captured detection events. Reproducing them on a system you do not own is unauthorised. Reproducing them on a lab you own is fair game and is how a defender validates that the detection chain still works after a Sysmon config change.

### 3.1 Encoded PowerShell payload generation

```powershell
$cmd = "Get-LocalUser | Where-Object { $_.Enabled -eq $true }"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host "Encoded: $encoded"
```

Then execute :

```
powershell.exe -EncodedCommand <base64_string>
```

Caveat : generating the Base64 from `cmd.exe` strips PowerShell `$_` and `$true` variables. Generate the Base64 inside PowerShell, not inside cmd, if you need the payload to survive transit intact.

### 3.2 Clean DNS query trigger

Edge produces noise. PowerShell produces a clean Sysmon Event 22.

```powershell
Resolve-DnsName example.com
```

### 3.3 Kerberoasting without third-party tools

```powershell
# 1. Pre-position : add a SPN to a target service account (attacker pre-step)
Set-ADUser -Identity svc_backup `
  -ServicePrincipalNames @{Add="HTTP/becode-backup.becode.corp.lab"}

# 2. Trigger : request the service ticket using pure .NET
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
  -ArgumentList "HTTP/becode-backup.becode.corp.lab"
```

No Rubeus, no Mimikatz. The DC will log Event 4769 with `Ticket Encryption Type = 0x17`.

### 3.4 AS-REP setup (manual UI step plus query)

The toggle is in `dsa.msc` : user Properties > Account tab > Account options > "Do not require Kerberos preauthentication".

Then verify which accounts are roastable with the query from 2.2 above.

### 3.5 AD enumeration via built-in cmdlets

```powershell
Get-ADComputer -Filter * | Select-Object Name, DNSHostName
Get-ADGroup    -Filter * | Select-Object Name, GroupScope
```

Captured by ScriptBlock logging (Event 4104) on whichever host they run from.

### 3.6 PSRemoting lateral movement

```powershell
$cred = Get-Credential
Enter-PSSession -ComputerName ws01.becode.corp.lab -Credential $cred
```

Sysmon Event 3 fires on the source with `DestinationPort = 5985`.

---

## 4. Day 2 inventory snippets

Quick references for verifying the AD structure after build.

```powershell
# List all OUs in the domain
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# List all enabled users
Get-ADUser -Filter {Enabled -eq $true} -Properties * |
  Select-Object SamAccountName, Department, Title

# List security groups created for BeCode Corp.
Get-ADGroup -Filter "Name -like 'GRP-*'" |
  Select-Object Name, GroupScope, GroupCategory

# Verify password policy
Get-ADDefaultDomainPasswordPolicy

# Verify GPO Security-Monitoring is linked
Get-GPO -Name "Security-Monitoring" | Select-Object DisplayName, GpoStatus
```

---

## See also

- `docs/02-build-walkthrough.md` for the surrounding context on each command
- `docs/03-detection-scenarios.md` and `docs/04-redblue-techniques.md` for the captured Event Viewer outputs each command produced
- `docs/05-lessons-learned.md` for the operational caveats (cmd.exe variable expansion damage, SwiftOnSecurity LSASS whitelist, Sysmon network filter)
