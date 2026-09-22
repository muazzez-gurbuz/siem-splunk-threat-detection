# SIEM Implementation & Threat Detection — Splunk Enterprise

**Team project (OAK Academy)** — deployed a centralized Splunk Enterprise SIEM, forwarded Windows Event Logs, Sysmon telemetry, and Linux authentication logs from endpoints, then built and validated 3 custom SOC detection use cases mapped to MITRE ATT&CK.

`SIEM` `Splunk Enterprise` `Splunk Universal Forwarder` `Sysmon` `SPL` `Log Correlation` `MITRE ATT&CK` `Threat Detection` `Dashboard Design` `Hydra` `Nmap`

![Final Security Monitoring Dashboard](siem-splunk-screenshots/01-final-security-dashboard.png)
*Centralized dashboard combining all three detections — KPIs, attack timeline, and detailed event tables.*

---

## Architecture

```
Linux Attacker (Hydra / Nmap)
        │
        ▼
┌─────────────────────────────┐
│ Windows Endpoint             │
│ Windows Event Logs           │
│ Sysmon Operational Logs      │
│ Universal Forwarder          │
└──────────────┬───────────────┘
               │ Forwarded Logs
               ▼
┌─────────────────────────────┐
│ Splunk Enterprise             │
│ Indexing · SPL Search         │
│ Dashboards · Reports          │
└─────────────────────────────┘
```

Linux authentication logs (`/var/log/auth.log`) were forwarded in parallel via a second Universal Forwarder.

## What I Did

| Area | Action | Result |
|---|---|---|
| **Linux Log Forwarding** | Installed Splunk Universal Forwarder on Ubuntu, resolved a CPU-compatibility precheck failure, configured `/var/log/auth.log` monitoring and forward-server config | Real-time Linux authentication events confirmed flowing into Splunk |
| **Windows Log Forwarding** | Installed Universal Forwarder on Windows via RDP access, configured Windows Event Log (Security) collection | Windows Security Events confirmed flowing into Splunk (`sourcetype=WinEventLog:Security`) |
| **Sysmon Deployment** | Installed Microsoft Sysmon, applied a community-maintained config template (Olaf Hartong), forwarded the Sysmon Operational channel | Detailed process-creation telemetry (Event ID 1) available in Splunk |
| **Log Verification** | Verified all three sources end-to-end with targeted SPL searches | Linux auth, Windows Security, and Sysmon logs all confirmed live |
| **Use Case Development** | Wrote 3 custom SPL detections, built supporting dashboard panels for each | 3 working detections mapped to MITRE ATT&CK |

## Log Sources Configured

![Linux authentication logs flowing into Splunk in real time](siem-splunk-screenshots/05-linux-auth-logs-in-splunk.png)
*25,954 Linux auth.log events ingested and searchable.*

![Windows Security Event Logs received in Splunk](siem-splunk-screenshots/06-windows-security-logs-splunk.png)

![Multiple log sources active — Sysmon, Windows Security/Application/System](siem-splunk-screenshots/07-multiple-log-sources-sysmon.png)
*Confirms Sysmon Operational, Windows Security, Application, and System logs are all being indexed alongside other infrastructure logs in the shared lab environment.*

### Linux Universal Forwarder — Install Notes

![Downloading the Universal Forwarder package on Linux](siem-splunk-screenshots/02-linux-forwarder-download.png)

The first installation attempt failed a CPU-compatibility precheck (`CPU Info upgrade precheck FAILED`) — resolved by setting `SPLUNK_SKIP_PREINSTALL_CPU_CHECKS_CORRUPTING_DATA_IF_UNSUPPORTED=1` for the lab VM, after which installation completed successfully:

![CPU compatibility issue resolved, installation successful](siem-splunk-screenshots/03-cpu-check-fix-success.png)

![Configuring the forward-server destination](siem-splunk-screenshots/04-forward-server-config.png)

---

## Use Case 1 — RDP Brute Force Detection

**Scenario:** Simulated a Hydra-based RDP brute force attack from the Linux attacker machine against the Windows endpoint.

**Detection logic:** Correlate failed (Event ID 4625) and successful (Event ID 4624) logons from the same source IP within a time window; flag when failed attempts ≥ 5.

```spl
(EventCode=4624 OR EventCode=4625) earliest=-24h
Source_Network_Address="<attacker_ip>"
Account_Name="<target_user>"
| stats count(eval(EventCode=4625)) as Failed
        count(eval(EventCode=4624)) as Success
        earliest(_time) as FirstAttempt latest(_time) as LastEvent
        values(Failure_Reason) as FailureReason
        values(Logon_Type) as LogonType
  by Source_Network_Address ComputerName
| where Failed>=5
| eval LogonType=case(LogonType=2,"Interactive",LogonType=3,"Network",LogonType=10,"RDP",true(),tostring(LogonType))
| convert ctime(FirstAttempt) ctime(LastEvent)
| table Source_Network_Address ComputerName Failed Success LogonType FirstAttempt LastEvent FailureReason
| sort -Failed
```

**Result:** The detection identified 5,560 failed logon attempts and one successful logon from the same source IP. This pattern was consistent with the simulated brute-force scenario.

*Query output is visible in the Brute Force Detection Summary table in the [Dashboard](#dashboard) section below.*

| MITRE ATT&CK | Technique |
|---|---|
| T1110 | Brute Force |

## Use Case 2 — Whoami Execution Detection (Post-Compromise Discovery)

**Scenario:** After simulated compromise, `whoami.exe` was executed to represent typical post-access user/context discovery.

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*whoami.exe"
| eval Technique="Discovery (MITRE T1033)"
| eval Time=strftime(_time,"%d/%m/%Y %H:%M:%S")
| table Time User Computer Image ParentImage CommandLine Technique
| rename Computer as Host, Image as Process, ParentImage as Parent_Process, CommandLine as Command, Technique as MITRE_Technique
| sort -Time
```

**Result:** 3 executions detected, parent process `cmd.exe` confirming interactive (manual) execution rather than an automated/legitimate script.

| MITRE ATT&CK | Technique |
|---|---|
| T1033 | System Owner/User Discovery |

## Use Case 3 — Network Scan Detection (Nmap/Zenmap)

**Scenario:** Nmap/Zenmap executed from the compromised Windows endpoint to simulate network reconnaissance.

![Nmap/Zenmap scan launched from the Windows endpoint](siem-splunk-screenshots/08-zenmap-nmap-scan-execution.png)

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*nmap.exe" OR Image="*zenmap.exe")
| eval Technique="Discovery (MITRE T1046)"
| eval Time=strftime(_time,"%d/%m/%Y %H:%M:%S")
| table Time User Computer Image ParentImage CommandLine Technique
| rename Computer as Host, Image as Process, ParentImage as Parent_Process, CommandLine as Command, Technique as MITRE_Technique
| sort -Time
```

**Result:** Scan execution detected and attributed to a Zenmap GUI-launched process, parent process `explorer.exe`.

| MITRE ATT&CK | Technique |
|---|---|
| T1046 | Network Service Discovery |

---

## Dashboard

![Dashboard detection tables — brute force, whoami, and Nmap detections](siem-splunk-screenshots/09-dashboard-detection-tables.png)

![Brute force attack timeline, zoomed](siem-splunk-screenshots/10-brute-force-timeline.png)
*Timeline panel shows the sharp spike in failed logins characteristic of automated Hydra activity, followed by the single successful authentication.*

![Nmap detection table detail](siem-splunk-screenshots/11-nmap-detection-table.png)

Dashboard combines 4 KPIs (Failed Logins, Successful Logins, Whoami Executions, Network Scan Detections), 1 timeline visualization, and 3 detection tables into a single SOC-analyst view.

## Attack Chain Summary

| Stage | Detection | MITRE ATT&CK |
|---|---|---|
| Initial Access | RDP Brute Force | T1110 |
| Discovery | `whoami.exe` execution | T1033 |
| Discovery | Nmap network scan | T1046 |

Correlating all three detections reconstructs a realistic end-to-end intrusion: credential compromise → user/context discovery → network reconnaissance.

## Key Takeaways

- Building the log pipeline (Universal Forwarder on both Linux and Windows, plus Sysmon) took more troubleshooting than the detections themselves — CPU precheck failures and forwarder configuration are real operational friction, not just "install and go"
- Sysmon's Event ID 1 (Process Creation) was essential for Use Cases 2 and 3 — Windows Security Logs alone show *how* an attacker got in, but not what they did afterward
- Correlating successful vs. failed logons (rather than just counting failures) reduced false-positive risk and made the brute-force detection far more actionable
- Mapping each detection to MITRE ATT&CK made it straightforward to reconstruct a coherent attack narrative from three independently-triggered alerts

---

*Team project completed as part of OAK Academy's Cybersecurity Engineering program in a controlled training lab environment. The cracked credential value from the brute-force simulation has intentionally been left out of this summary.*
