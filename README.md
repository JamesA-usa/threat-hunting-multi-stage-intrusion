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


### 2. Searched the `DeviceEvents` Table

At `2026-01-15T03:53:09Z`, a PowerShell-initiated reflective/in-memory load was observed (ClrUnbackedModuleLoaded). 

**Query used to locate events:**

```kql
DeviceEvents
| where TimeGenerated > ago(60d)
| where DeviceName == "as-pc2"
| where ActionType == "ClrUnbackedModuleLoaded"
| where InitiatingProcessCommandLine has "powershell"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

Image here for table 2


## To be edited

### 3. Searched the `DeviceProcessEvents` Table

At `2026-01-15T03:58:55Z`, payload activity occured using Daniel_Richardson_CV.pdf.exe to conduct recon.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where DeviceId == "7d6cd5dbcd3ff168bad38b14f5f27dfd5a9b77c5"
| where ProcessCommandLine has_any (
   "whoami", "qwinsta", "quser", "query user", "tasklist", "systeminfo", "hostname",
   "ipconfig", "net user", "net localgroup", "net group", "net view",
   "wmic useraccount", "wmic process", "wmic computersystem",
   "nltest", "dsquery", "gpresult", "klist", "setspn"
)
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

image for table 3 here

### 4. Searched the `DeviceFileEvents` Table

At `2026-01-15T04:08:32Z`, AnyDesk was downloaded via certutil.exe.

**Query used to locate events:**

```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where DeviceId == "7d6cd5dbcd3ff168bad38b14f5f27dfd5a9b77c5"
| where FileName =~ "AnyDesk.exe"
| order by Timestamp asc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

image for table 4 here




### 5. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:10:06Z`, AnyDesk was executed to maintain access to a compromised system after the initial intrusion.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where DeviceId == "7d6cd5dbcd3ff168bad38b14f5f27dfd5a9b77c5"
| where FileName =~ "AnyDesk.exe"
| where InitiatingProcessCommandLine contains "cmd"
| order by Timestamp asc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

image for table 5 here




### 6. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:18:44Z`, failed remote execution atttempts began, using WMIC and PsExec, against AC-PC2 were observed. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where AccountDomain in~ ("as-pc1","as-pc2","as-srv")
| where FileName in~ ("psexec.exe","wmic.exe","winrs.exe","sc.exe","powershell.exe")
| where ProcessCommandLine contains "cmd"
| where ProcessCommandLine contains "AS-PC2"
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessSHA256
```

image for table 6



### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table

### 4. Searched the `DeviceNetworkEvents` Table
