# Evidence

This directory is a placeholder in v1. The complete v1 deliverable is textual : verbatim Event Viewer captures, detection rule logic, and design rationale all live inside `docs/`. No screenshots, no exported GPO HTML, no Sigma rule files are committed yet.

## Why text first, visuals later

v1 prioritises proving comprehension of the build and the detection chain over visual polish. Every captured Event Viewer output quoted in `docs/03-detection-scenarios.md` and `docs/04-redblue-techniques.md` is real, came from a real run on the Azure lab on 23-24 March 2026, and is anonymized per the rules below.

Visual artifacts (screenshots, GPO HTML exports, Sigma rules, SIEM integration code, replay scripts) are the v2 deliverable. They will be added in a separate session after rapatriating files from the Azure VM and investing the SIEM stand-up time.

## v2 Roadmap

### Screenshots ( `evidence/screenshots/` )

Targeted Event Viewer captures, one per major detection signal :

- [ ] `01-kerberoasting-4769.png` (Service Name `svc_backup`, Ticket Encryption Type `0x17`)
- [ ] `02-asrep-4768.png` (Account `svc_ftp`, Pre-Authentication Type `0`)
- [ ] `03-spray-ntlm-4625.png` (`claire.dupont`, Workstation `WS01`, Source IP)
- [ ] `04-powershell-4104-decoded.png` (encoded command decoded by ScriptBlock logging)
- [ ] `05-lsass-sysmon11.png` (TargetFilename `lsass.DMP`, Image `taskmgr.exe`)
- [ ] `06-external-attack-185.156.73.74.png` (bonus, if the events are still in the DC log)

### GPO HTML reports ( `evidence/gpo-reports/` )

Already generated on the VM during the lab, stored in `Documents\windows\` on `dc01`. To rapatriate and place here :

- [ ] `default-domain-policy.html`
- [ ] `security-monitoring.html`

### Detection rules ( `detection-rules/` )

Formal Sigma rule files for the 11 MITRE techniques mapped in `docs/06-mitre-mapping.md`, with conversion verified on at least two SIEMs :

- [ ] 11 Sigma YAML files (one per technique)
- [ ] Splunk SPL ports
- [ ] Elastic KQL ports

### SIEM integration ( `siem-integration/` )

A docker-compose Elastic stack and forwarder config so a reader can replay the detection chain locally :

- [ ] `docker-compose.yml` for Elasticsearch + Kibana + Winlogbeat
- [ ] `winlogbeat.yml` configured to forward `dc01` + `ws01` Windows logs
- [ ] Example Kibana dashboards covering the 11 detection signals
- [ ] End-to-end documentation : Windows host > Winlogbeat > Elastic > Kibana > alert

### Test harness ( `tests/` )

Replayable PowerShell scripts that exercise each technique against a freshly built lab, validating that detection still fires :

- [ ] 6 native scenario replays
- [ ] 5 Red/Blue technique replays
- [ ] CI mode : run on a schedule, assert that expected Event IDs surfaced within N minutes

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
- SIEM-agnostic detection rule logic for all 11 techniques

What v1 documentation does NOT contain :

- Visual artifacts (Event Viewer screenshots, rendered HTML GPO reports)
- The Event 4698 of the actual `ServerMaintenanceHelper` task (only the false-positive Windows Defender scan was captured in working notes)
- Full Event 4768 AS-REP roasting XML structure (only key fields confirmed)
- Sysmon Event 1 for `taskmgr.exe` as parent of the LSASS dump
- Day 1 setup verbatim outputs (DC promotion, DSRM key generation)
- Day 2 user / group / OU creation verbatim outputs (consolidated in `lab-documentation.md` tables but raw events not preserved)

These gaps do not affect v1 quality. Anything that requires visual evidence belongs to v2 and will be filled when the VM is restarted to capture screenshots.
