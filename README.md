# Incident Investigation Report: AsyncRAT Infection Chain Analysis

<img width="1248" height="862" alt="1" src="https://github.com/user-attachments/assets/7cbe096f-096a-4459-8d9c-9b1f5c46a7f1" />




## 1. Executive Summary
- **Incident Type:** Phishing / Script-based Malware Delivery
- **Malware Family:** AsyncRAT
- **Severity:** High
- **Analyst:** [Ahmed Raafat]
- **Overview:** Investigation of an attack vector utilizing deceptive files, leveraging native Windows utilities (LOLBins) for defense evasion, and establishing C2 communication.

---

## 2. Attack Chain (Kill Chain Overview)
1. **Initial Access:** Execution of a deceptive file or script payload on the victim's workstation.
2. **Execution & Script Host:** Triggered via Windows Script Host (`WScript.exe`) to execute embedded logic.
3. **Payload Retrieval:** `PowerShell` invoked to download the payload (`mdm.jpg`) from an external malicious IP.
4. **Defense Evasion (Process Injection):** Reflected/injected code into a legitimate Microsoft .NET binary (`RegSvcs.exe`) to evade security controls.

---

## 3. Visual Analysis & Investigation Steps

### **Initial Access**
## Initial Access 
<img width="1762" height="758" alt="Screenshot 2026-10-26 181001" src="https://github.com/user-attachments/assets/3d2e3b41-2b1d-48e2-ad0c-014e32c6da1a" />

> **Figure 1:** Initial file analysis on VirusTotal, showing the detection rate and warning flags confirming the malicious nature of the dropped file.

### **Execution & Process Injection**
## Process Tree
<img width="758" height="110" alt="Screenshot 2026-10-27 080733" src="https://github.com/user-attachments/assets/df6c95ec-2a90-4410-850f-8bb0217676b4" />

---




<img width="498" height="296" alt="Screenshot 2026-10-27 080745" src="https://github.com/user-attachments/assets/3a0c3b50-e99f-47c0-8c75-f3101d63d972" />

> **Figure 2:** Sandbox Process Tree showing the execution chain: starting from script execution via `wscript.exe`, spawning `powershell.exe` for payload download, and injecting into the legitimate system binary `RegSvcs.exe` (LOLBin) for defense evasion.

### **Network & C2 Traffic**
## Network Activity
<img width="1849" height="868" alt="Screenshot 2026-10-27 081824" src="https://github.com/user-attachments/assets/18d6b722-5156-4fe1-8681-4d3e8ac76c6a" />

> **Figure 3:** Network traffic analysis (PCAP) capturing outbound connection from the infected host to the external Command and Control (C2) server over the suspicious IP and port.

<img width="1609" height="333" alt="Screenshot 2024-05-15 162215" src="https://github.com/user-attachments/assets/6f04e6ee-6c59-4620-a213-20c4fcfb61be" />

> **Figure 4:** Indicators of Compromise (IOCs) including dropped filenames and their SHA256 hashes, essential for threat hunting and blocking.

---

## 4. Indicators of Compromise (IOCs) Table
| Type | Indicator | Description |
| :--- | :--- | :--- |
| **File Name** | `mdm.jpg`, `update.vbs`, `payload.exe` | Dropped payload files in Temp directory |
| **Malicious IP** | `45.126.209.4:222` | Command & Control (C2) Server |
| **Process Path** | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | Target LOLBin used for process injection |

---

## 5. Detection & Mitigation Recommendations
- **Monitor LOLBins:** Monitor execution of .NET framework binaries (`RegSvcs.exe`, `RegAsm.exe`) when spawned by script engines or unexpected parent processes.
- **Network Restrictions:** Block outbound connections to unverified external IPs on non-standard ports.
- **Script Block Logging:** Enable PowerShell Script Block Logging (Event ID 4104) to capture de-obfuscated script content.
