# Incident Investigation Report: AsyncRAT Infection Chain Analysis

## 1. Executive Summary
- **Incident Type:** Phishing / Script-based Malware Delivery
- **Malware Family:** AsyncRAT
- **Severity:** High
- **Analyst:** [Ahmed Raafat]
- **Overview:** Investigation of an attack vector utilizing macro-enabled files/scripts, leveraging native Windows utilities (LOLBins) for defense evasion and establishing C2 communication.

## 2. Attack Chain (Kill Chain Overview)
1. **Initial Access:** Execution of a deceptive file/script payload.
2. **Execution & Script Host:** Triggered via Windows Script Host (`WScript.exe`) to execute embedded logic.
3. **Payload Retrieval:** `PowerShell` invoked to download the payload (`mdm.jpg`) from an external malicious IP.
4. **Defense Evasion (Process Injection):** Reflected/injected code into a legitimate Microsoft .NET binary (`RegSvcs.exe`) to evade security controls.

## 3. Indicators of Compromise (IOCs)
| Type | Indicator | Description |
| :--- | :--- | :--- |
| **File Name** | `mdm.jpg` | Disguised PE payload (AsyncRAT) |
| **File Hash (SHA256)** | `[1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798]` | Unique sample identifier |
| **Malicious IP** | `45.126.209.4:222` | Command & Control (C2) Server |
| **Process Path** | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | Target LOLBin used for injection |

## 4. Detection & Mitigation Recommendations
- **Monitor LOLBins:** Monitor execution of .NET framework binaries (`RegSvcs.exe`, `RegAsm.exe`) when spawned by script engines or unexpected parent processes.
- **Network Restrictions:** Block outbound connections to unverified external IPs on non-standard ports.
- **Script Block Logging:** Enable PowerShell Script Block Logging (Event ID 4104) to capture de-obfuscated script content.
