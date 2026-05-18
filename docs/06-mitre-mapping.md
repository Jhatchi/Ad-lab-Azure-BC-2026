# 06. MITRE ATT&CK Mapping

Consolidated table of the 11 techniques exercised in this lab. Six come from the Day 3 native scenarios (`03-detection-scenarios.md`), five come from the Red/Blue bonus exercises (`04-redblue-techniques.md`).

## 11 Techniques, Coverage Summary

| # | MITRE ID      | Technique                                                  | Tactic              | Event ID(s)        | Log location                                     | Native coverage | Sysmon coverage | Detection rate |
|---|---------------|------------------------------------------------------------|---------------------|--------------------|--------------------------------------------------|-----------------|-----------------|----------------|
| 1 | T1110.003     | Password Spraying (Kerberos)                               | Credential Access   | 4771               | Security (DC)                                    | Full            | N/A             | 1 / 1          |
| 2 | T1110.003     | Password Spraying (NTLM fallback)                          | Credential Access   | 4625               | Security (DC)                                    | Full            | N/A             | 1 / 1          |
| 3 | T1136.001     | Create Account (backdoor)                                  | Persistence         | 4720 + 4728 + 4726 | Security (DC)                                    | Full            | N/A             | 1 / 1          |
| 4 | T1087.002     | Account Discovery : Domain Account                         | Discovery           | 4104, Sysmon 1     | PowerShell Operational, Sysmon Operational       | Partial         | Full            | 1 / 1          |
| 5 | T1027         | Obfuscated Files or Information (encoded PowerShell)       | Defense Evasion     | 4104, 4688         | PowerShell Operational, Security                 | Full (with ScriptBlock) | Bonus    | 1 / 1          |
| 6 | T1053.005     | Scheduled Task / Job : Scheduled Task                      | Persistence         | 4698               | Security (DC)                                    | Full            | Bonus           | 1 / 1          |
| 7 | T1071.001 / T1071.004 | Application Layer Protocol (Web + DNS)              | Command and Control | Sysmon 22          | Sysmon Operational                               | None            | Full            | 1 / 1          |
| 8 | T1558.003     | Kerberoasting                                              | Credential Access   | 4769               | Security (DC)                                    | Full            | N/A             | 1 / 1          |
| 9 | T1558.004     | AS-REP Roasting                                            | Credential Access   | 4768               | Security (DC)                                    | Full            | N/A             | 1 / 1          |
| 10| T1003.001     | OS Credential Dumping : LSASS Memory                       | Credential Access   | Sysmon 10, Sysmon 11 | Sysmon Operational                             | None            | Partial (10 filtered, 11 worked) | 1 / 1 |
| 11| T1021.006     | Remote Services : Windows Remote Management (PSRemoting)   | Lateral Movement    | Sysmon 3, 4624     | Sysmon Operational (source), Security (target)   | Partial         | Full            | 1 / 1          |

**Overall detection rate : 11 / 11.**

## Tactics Distribution

| Tactic               | Techniques |
|----------------------|------------|
| Credential Access    | 5          |
| Persistence          | 2          |
| Discovery            | 1          |
| Defense Evasion      | 1          |
| Command and Control  | 1          |
| Lateral Movement     | 1          |

The lab leans heavily on Credential Access because that is where Active Directory is most exposed and where the most distinctive detection signals live (Kerberos encryption type, pre-auth flag, NTLM substatus codes). A v2 expansion would diversify toward Initial Access (phishing payload delivery), Execution (additional LOLBin variants), and Impact (ransomware-style file activity).

## Native vs Sysmon Coverage

| Category                                                | Count |
|---------------------------------------------------------|-------|
| Native logging alone is sufficient                      | 5     |
| Native logging gives partial coverage, Sysmon completes | 4     |
| Sysmon is the only source of signal                     | 2     |

The two Sysmon-only signals are :

- DNS query telemetry (Sysmon Event 22), for T1071.001 / T1071.004
- LSASS memory dump file artifact (Sysmon Event 11), for T1003.001

Both are blind spots in default Windows auditing. Both are common attacker techniques. Deploying Sysmon (or an EDR that provides the same telemetry) is therefore not a "nice to have", it is mandatory coverage for two distinct MITRE techniques.

## v2 Plan

v2 plan : Event Viewer screenshots for the 5-6 most distinctive captures, plus gpo_report.html exports (Default Domain Policy + Security-Monitoring) rapatriated from the Azure VM. See `evidence/README.md` for the full v2 scope.
