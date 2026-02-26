<img src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/threat%20hunt%20pdf.png"> 

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Python
- PyCharm

##  Scenario

An employee on device AS-PC1 executed a file that appeared to be a legitimate PDF resume but was in fact a disguised executable named Daniel_Richardson_CV.pdf.exe. The objective of this investigation is to identify and analyze any resulting intrusion activity to mitigate potential risks. If malicious activity is confirmed, management will be notified in accordance with incident response procedures.

### High-Level Intrusion IoC Discovery Plan

- **Identify Initial Compromise & Execution Artifacts**: Search for abnormal process execution, suspicious file hashes, disguised executables, unusual outbound connections, and command-line anomalies using the following tables:
   - DeviceProcessEvents
   - DeviceFileEvents
   - DeviceEvents
   - DeviceNetworkEvents
- **Discover Lateral Movement & Persistence Indicators**: Hunt for remote authentication events (RDP, SMB, PsExec), failed and successful logons, account modifications, scheduled task creation, service installs, and privilege escalation commands. Capture newly created accounts, modified Administrator status, task names, service names, and remote session origins as secondary IoCs.
- **Detect Staging, Exfiltration & Defense Evasion**: Investigate archive creation, large file compression, network share enumeration, abnormal outbound traffic, log clearing (wevtutil), and in-memory module execution events.

---

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table

- **Timestamp:** `2026-01-15T03:47:10Z`
- **Event:** The file `daniel_richardson_cv.pdf.exe` was executed by an employee and subsequently established outbound communication with `cdn.cloud-endpoint.net`, consistent with command-and-control (C2) activity.
- **Action:** Malicious payload deployed.
- **File Path:** c:\users\sophie.turner\downloads\daniel_richardson_cv\daniel_richardson_cv.pdf.exe

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(60d)
| where InitiatingProcessFileName =~ "Daniel_Richardson_CV.pdf.exe"
| where InitiatingProcessSHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| where isnotempty(RemoteUrl)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RemoteUrl, InitiatingProcessFolderPath, InitiatingProcessSHA256
```
<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/t1.png">


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

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%202.png">


### 3. Searched the `DeviceProcessEvents` Table

At `2026-01-15T03:58:55Z`, payload activity occurred using Daniel_Richardson_CV.pdf.exe to conduct recon.

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

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%203.png">


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

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%204.png">


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

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%205.png">


### 6. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:18:44Z` failed remote execution attempts began using WMIC and PsExec against AC-PC2 were observed. 

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

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%206.png">



### 7. Searched the `DeviceLogonEvents` Table

At `2026-01-15T04:39:57Z`, a login to AS-PC2 was successfull using the username david.mitchell.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "as-pc2"
| where AccountDomain == "as-pc2"
| where ActionType == "LogonSuccess"
| where Timestamp > ago(60d)
| order by Timestamp desc
| project TimeGenerated, DeviceName, AccountName, ActionType, RemoteDeviceName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%207.png">



### 8. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:40:31Z` on AS-PC2, the account david.mitchell executed net.exe user Administrator /active:yes, enabling the built-in local Administrator account. This action is consistent with privilege escalation and potential persistence techniques.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where DeviceName == "as-pc2"
| where FileName =~ "net.exe"
| where AccountName == "david.mitchell"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%208.png">




### 9. Searched the `DeviceFileEvents` Table

At `2026-01-15T04:43:52Z`, sensitive file BACS_Payments_Dec2025.ods was accessed on AS-SRV.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated > ago(60d)
| where DeviceName has "as-"
| where FileName has_any (
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",
    ".pdf",".csv",".txt",".rtf",
    ".json",".yaml",".yml",
    ".sql",".bak",".ods", ".lnk"
)
| where FileName contains "BACS"
| where InitiatingProcessAccountName != "system"
| order by Timestamp desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/Table%209.png">


### 10. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:52:32Z`, the account david.mitchell created a scheduled task named “MicrosoftEdgeUpdateCheck” that is configured to run C:\Users\Public\RuntimeBroker.exe daily at 3:00 AM with the highest privileges. This establishes persistence by automatically executing that program — likely a disguised or malicious binary—on a recurring schedule.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where DeviceName == "as-pc2" 
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2010.png">


### 11. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:54:55Z`, the system AS-PC2 initiated a Remote Desktop connection using mstsc.exe to the host 10.1.0.203. The presence of InitiatingProcessRemoteSessionDeviceName=AS-PC1 indicates the session originated from AS-PC1, representing successful lateral movement via RDP.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessRemoteSessionDeviceName == "AS-PC1"
| where FileName == "mstsc.exe"
| order by Timestamp desc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2011.png">


### 12. Searched the `DeviceProcessEvents` Table

At `2026-01-15T04:57:50Z` on as-pc1, the command net.exe localgroup Administrators svc_backup /add was executed, adding the account svc_backup to the local Administrators group. This action grants elevated privileges to that account and is consistent with establishing persistence or creating a backdoor for continued administrative access.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where DeviceName == "as-pc1"
| where InitiatingProcessCommandLine contains "/add"
| where InitiatingProcessCommandLine contains "administrator"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2012.png">



### 13. Searched the `DeviceFileEvents` Table

At `2026-01-15T04:59:04Z` on as-srv, a compressed archive named Shares.7z was created, indicating data was packaged for staging or potential exfiltration. The associated SHA256 hash confirms the specific file instance, supporting evidence of possible data collection and preparation for transfer.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated > ago(60d)
| where DeviceName == "as-srv"
| where FileName matches regex @"\.(zip|7z)$"
| where FileName != "VMAgentLogs.zip"
//7zG.exe means the GUI for this tool was opened to create the 7z file
| where InitiatingProcessCommandLine contains "7zG.exe"
| order by Timestamp desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2013.png">


### 14. Searched the `DeviceProcessEvents` Table

At `2026-01-15T05:07:42Z` on as-srv, the command wevtutil.exe cl Security and the command wevtutil.exe cl System were executed to clear the Windows Security event log. This action removes audit records and is commonly associated with defense evasion to conceal malicious activity.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-15 00:00:00) .. datetime(2026-01-15 23:59:59))
| where DeviceName == "as-srv"
| where ProcessCommandLine has "cl"
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessSHA256
```

<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2014.png">

### 15. Searched the `DeviceEvents` Table

At `2026-01-15T05:09:53Z` on as-pc1, a .NET assembly was loaded into notepad.exe without a corresponding backing file on disk, as indicated by a ClrUnbackedModuleLoaded event. This behavior is consistent with in-memory execution of credential theft tooling, suggesting potential malicious code injection into a legitimate process for stealth.

**Query used to locate events:**

```kql
DeviceEvents
| where TimeGenerated > ago(60d)
| where DeviceName has "as-"
| where ActionType == "ClrUnbackedModuleLoaded"
| where InitiatingProcessFileName =~ "notepad.exe"
| order by Timestamp desc
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, InitiatingProcessFileName, InitiatingProcessSHA256
```
<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2015.png">


### 16. Searched the `DeviceProcessEvents` Table

At `2026-01-27T22:17:40Z` on as-srv, the account as.srv.administrator executed net.exe view \\10.1.0.154 to enumerate available network shares on the remote host. This command is commonly used during reconnaissance to identify accessible shared resources for potential lateral movement or data discovery.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where DeviceName has "as-"
| where ProcessCommandLine has "view \\"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/JamesA-usa/threat-hunting-multi-stage-intrusion/blob/main/table%2016.png">

---

## Summary

A multi-stage intrusion starting with execution of a masqueraded PDF executable (Daniel_Richardson_CV.pdf.exe) on AS-PC1. The payload performed host reconnaissance, established outbound C2 communications to cloud-endpoint.net infrastructure, and used in-memory .NET loading (ClrUnbackedModuleLoaded) consistent with fileless post-exploitation tooling. The actor deployed AnyDesk for persistence, attempted multiple lateral movement methods (WMIC/PsExec), then pivoted successfully using RDP (mstsc.exe) to AS-PC2 and accessed sensitive payroll files on AS-SRV. Data was staged into a 7-Zip archive (Shares.7z) and the attacker performed anti-forensics via wevtutil log clearing.

---

## Response Taken

A full forensic triage (memory capture, persistence review, scheduled tasks, AnyDesk removal, log forwarding validation) was conducted. Identified C2 domains and hashes were blocked and recorded to prevent re-compromise. AS-PC1, AS-PC2, and AS-SRV were isolated from the network to contain the intrusion and credentials were reset for all impacted accounts, including Administrator, david.mitchell, sophie.turner, and svc_backup. The employee's manager was notified.

---

