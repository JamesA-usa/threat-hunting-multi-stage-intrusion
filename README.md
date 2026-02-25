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

At `2026-01-15T03:47:10Z`, the payload established outbound connections using domain `cdn.cloud-endpoint.net` for command and control (C2). The process responsible for the C2 traffic was `daniel_richardson_cv.pdf.exe`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(60d)
| where InitiatingProcessFileName =~ "Daniel_Richardson_CV.pdf.exe"
| where InitiatingProcessSHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| where isnotempty(RemoteUrl)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessSHA256
```
<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%201.png">


## To be edited

### 2. Searched the `DeviceNetworkEvents` Table

At `2026-01-15T03:53:09Z`,

Reflective/in-memory load observed (ClrUnbackedModuleLoaded)


### 3. Searched the `DeviceNetworkEvents` Table

At `2026-01-15T03:58:55Z`,

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table
