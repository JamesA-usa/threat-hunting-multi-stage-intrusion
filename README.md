# Threat Hunt Report: PDF Executable -> Multi-Stage Intrusion

<img src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/threat%20hunt%20pdf.png"> 

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Python
- PyCharm

##  Scenario

A multi-stage intrusion starting with execution of a masqueraded PDF executable (Daniel_Richardson_CV.pdf.exe) on AS-PC1. The payload performed host reconnaissance, established outbound C2 communications to cloud-endpoint.net infrastructure, and used in-memory .NET loading (ClrUnbackedModuleLoaded) consistent with fileless post-exploitation tooling. The actor deployed AnyDesk for persistence, attempted multiple lateral movement methods (WMIC/PsExec), then pivoted successfully using RDP (mstsc.exe) to AS-PC2 and accessed sensitive payroll files on AS-SRV. Data was staged into a 7-Zip archive (Shares.7z) and the attacker performed anti-forensics via wevtutil log clearing.

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table

The payload established outbound connections using domain 'cdn.cloud-endpoint.net' for command and control.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "wale-threat-hun"
| where InitiatingProcessAccountName == "labuser"
| where FileName startswith "tor"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-scenario-tor/blob/main/1-DeviceFileEvents.jpg">


Daniel_Richardson_CV.pdf.exe started started the infection chain for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-02-02 19:43:52Z`. These events began at `2026-02-02 19:41:20Z`.
