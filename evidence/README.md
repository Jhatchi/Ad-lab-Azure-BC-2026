# Evidence

This directory holds the visual deliverables of the lab : 2 Event Viewer screenshots and 2 GPO HTML reports rapatriated from the Azure VM. They complement the textual captures already embedded in `docs/03-detection-scenarios.md`, `docs/04-redblue-techniques.md`, and `docs/05-lessons-learned.md`.

Every captured Event Viewer output quoted across `docs/` is real, came from a real run on the Azure lab on 23-24 March 2026, and is anonymized per the rules at the bottom of this file.

## Visual artifacts

### Screenshots ( `evidence/screenshots/` )

- `01-kerberoasting-4769-rc4.png` : Event 4769 with Service Name `svc_backup` and Ticket Encryption Type `0x17` (RC4-HMAC), captured during Day 3 on 24/03/2026 at 13:23:00.
- `02-external-attack-4625-185.156.73.74.png` : Event 4625 from external IP `185.156.73.74`, captured on 20/03/2026 (four days before the planned Day 3 of the lab, during the open monitoring window on the internet-exposed DC).

### GPO HTML reports ( `evidence/gpo-reports/` )

Generated on the VM during the lab, stored in `Documents\windows\` on `dc01`, rapatriated and converted from UTF-16 (Edge save-as default) to UTF-8 for repository consistency. Both reports are clickable navigable HTML, not just textual exports.

- `01-default-domain-policy.html` : password policy, account lockout, Kerberos policy.
- `02-security-monitoring-policy.html` : audit policy (Kerberos, Logon, Account Management, Process creation with full command line), PowerShell ScriptBlock and Module logging.

### Hostname transparency note

Screenshots in `evidence/screenshots/` show the real lab hostname `Johan-dc01.becode.corp.lab`. Throughout the textual documentation (`docs/`), this same machine is referred to as `dc01` for brevity and convention. They are the same system.

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

## Honest Coverage Disclosure

What this lab documents :

- Verbatim Event Viewer outputs for 11 techniques, captured during real test runs on 23-24 March 2026
- Real PowerShell trigger workflows (Kerberoasting, AS-REP setup, PSRemoting prep, NLA bypass)
- Cross-referenced consistency checks (logon IDs, SIDs, timestamps align across multiple events of the same chain)
- Native Event Viewer detection logic for all 11 techniques
- 2 Event Viewer screenshots (Kerberoasting RC4 and external attack 4625) and 2 GPO HTML reports

Known gaps, kept transparent rather than papered over :

- The Event 4698 of the actual `ServerMaintenanceHelper` task (only the false-positive Windows Defender scan was captured in working notes)
- Full Event 4768 AS-REP roasting XML structure (only key fields confirmed)
- Sysmon Event 1 for `taskmgr.exe` as parent of the LSASS dump
- Day 1 setup verbatim outputs (DC promotion, DSRM key generation)
- Day 2 user / group / OU creation verbatim outputs (consolidated in `lab-documentation.md` tables but raw events not preserved)

These gaps do not affect the detection-coverage claim (11 / 11 techniques detected). They are pure observability artifacts whose absence reflects what was captured at the moment of the run, not a hole in the detection chain.
