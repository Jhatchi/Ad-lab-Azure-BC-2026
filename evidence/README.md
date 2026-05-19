# Evidence

This directory holds the v2 visual deliverables : 2 Event Viewer screenshots and 2 GPO HTML reports rapatriated from the Azure VM. The textual v1 deliverable (verbatim Event Viewer captures, native detection event mapping, design rationale) remains in `docs/`.

## Why text first, visuals later

v1 prioritised proving comprehension of the build and the detection chain over visual polish. Every captured Event Viewer output quoted in `docs/03-detection-scenarios.md` and `docs/04-redblue-techniques.md` is real, came from a real run on the Azure lab on 23-24 March 2026, and is anonymized per the rules below.

v2 adds visual artifacts (Event Viewer screenshots, GPO HTML exports) rapatriated from the Azure VM on 19 May 2026.

## v2 Roadmap

### Screenshots ( `evidence/screenshots/` ) - SHIPPED IN v2

Targeted Event Viewer captures :

- [x] `01-kerberoasting-4769-rc4.png` (Service Name `svc_backup`, Ticket Encryption Type `0x17`, captured during Day 3, 24/03/2026 13:23:00)
- [x] `02-external-attack-4625-185.156.73.74.png` (Event 4625 from external IP `185.156.73.74`, captured 20/03/2026, 4 days before the planned Day 3 of the lab)
- [ ] `03-asrep-4768.png` (Account `svc_ftp`, Pre-Authentication Type `0`) - deferred
- [ ] `04-spray-ntlm-4625.png` (`claire.dupont`, Workstation `WS01`, Source IP) - deferred
- [ ] `05-powershell-4104-decoded.png` (encoded command decoded by ScriptBlock logging) - deferred
- [ ] `06-lsass-sysmon11.png` (TargetFilename `lsass.DMP`, Image `taskmgr.exe`) - deferred

### GPO HTML reports ( `evidence/gpo-reports/` ) - SHIPPED IN v2

Generated on the VM during the lab, stored in `Documents\windows\` on `dc01`, rapatriated and converted from UTF-16 (Edge save-as default) to UTF-8 for repository consistency. Both reports are clickable navigable HTML, not just textual exports :

- [x] `01-default-domain-policy.html` (password policy, account lockout, Kerberos policy)
- [x] `02-security-monitoring-policy.html` (Advanced Audit Policy, PowerShell ScriptBlock and Module logging, Command line in process creation)

### Hostname transparency note

Note: screenshots in `evidence/screenshots/` show the real lab hostname `Johan-dc01.becode.corp.lab`. Throughout the textual documentation (`docs/`), this same machine is referred to as `dc01` for brevity and convention. They are the same system.

## Anonymization Rules Applied to v1 Docs

All published `docs/*.md` files apply these rules to outputs captured during the lab. The single exception is `185.156.73.74`, which is preserved as the external storytelling asset (see `docs/05-lessons-learned.md` section 1).

| Source value                    | Published placeholder |
|---------------------------------|-----------------------|
| Real DC hostname                | `dc01`                |
| Real client hostname            | `ws01`                |
| Real DC private IP              | `<DC_PRIVATE_IP>`     |
| Real client private IP          | `<WS_PRIVATE_IP>`     |
| Real DC public IP               | `<PUBLIC_IP_REDACTED>`|
| DHCP scope range                | `<DHCP_SCOPE>`        |
| SIDs (e.g. `S-1-5-21-...`)      | `{REDACTED}`          |
| Logon IDs (e.g. `0xC18F5`)      | `{REDACTED}`          |
| ScriptBlock IDs (GUIDs)         | `{REDACTED}`          |
| Kerberos token UUIDs            | `{REDACTED}`          |
| `185.156.73.74` (external)      | **preserved**         |
| `repadmin.exe` Microsoft hashes | preserved (public MS) |

The personas used inside the lab (`claire.dupont`, `alice.sysadmin`, `svc_backup`, etc.) are fictional BeCode-Corp characters, not real identities, and are kept as-is.

## Honest Coverage Disclosure (v1 scope)

What v1 documentation contains :

- Verbatim Event Viewer outputs for 11 techniques, captured during real test runs on 23-24 March 2026
- Real PowerShell trigger workflows (Kerberoasting, AS-REP setup, PSRemoting prep, NLA bypass)
- Cross-referenced consistency checks (logon IDs, SIDs, timestamps align across multiple events of the same chain)
- Native Event Viewer detection logic for all 11 techniques

What v1 documentation does NOT contain :

- Visual artifacts (Event Viewer screenshots, rendered HTML GPO reports)
- The Event 4698 of the actual `ServerMaintenanceHelper` task (only the false-positive Windows Defender scan was captured in working notes)
- Full Event 4768 AS-REP roasting XML structure (only key fields confirmed)
- Sysmon Event 1 for `taskmgr.exe` as parent of the LSASS dump
- Day 1 setup verbatim outputs (DC promotion, DSRM key generation)
- Day 2 user / group / OU creation verbatim outputs (consolidated in `lab-documentation.md` tables but raw events not preserved)

These gaps do not affect v1 quality. Anything that requires visual evidence belongs to v2 and will be filled when the VM is restarted to capture screenshots.
