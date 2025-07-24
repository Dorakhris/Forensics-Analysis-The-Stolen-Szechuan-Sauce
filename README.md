# Digital Forensics Case Study: The Stolen Szechuan Sauce

## Executive Summary
This report details a full-scale digital forensics and incident response (DFIR) investigation into a data breach involving the theft of a proprietary recipe. Inspired by a CTF challenge, this case study simulates a real-world scenario where an attacker breached the network, moved laterally, deployed malware, and exfiltrated sensitive data.

Using a comprehensive toolkit including **Autopsy, Wireshark, FTK Imager, and Volatility**, I performed a forensic analysis of disk images, memory dumps, and network captures. The investigation successfully reconstructed the entire attack chain, from the initial **RDP brute-force** entry to the deployment of a **Cobalt Strike/Meterpreter payload** and the final data exfiltration.

All findings are mapped to the **MITRE ATT&CK framework**, and the report concludes with a set of strategic hardening recommendations aligned with **NIST 800-53** and **ISO 27001**, demonstrating an end-to-end DFIR and GRC capability.

**Date:** September 2024

**Analyst:** Dorathy Christopher

---

The investigation revealed a clear, multi-stage attack lifecycle. I traced the attacker's actions chronologically through forensic artifacts.

### Phase 1: Initial Access & Reconnaissance
*   **Vector:** Remote Desktop Protocol (RDP) Brute-Force
*   **Evidence:** Analysis of network traffic (`.pcap` file in Wireshark) and Windows Event Logs (`Security.evtx` in Autopsy) revealed a high volume of failed login attempts (**Event ID 4625**) originating from the IP address `194.61.24.102`.
*   **Success:** On **2020-09-19 at 02:19:13 UTC-7**, the attacker successfully authenticated to the domain controller `DC01` (10.42.85.10) as the Administrator.

### Phase 2: Execution & Persistence
*   **Payload Delivery:** Immediately following the successful login, the attacker used the established RDP session to download the primary payload, `coreupdater.exe`, from their IP (`194.61.24.102`) via an unencrypted HTTP transfer.
*   **Malware Deployed:** Analysis of the `coreupdater.exe` hash on VirusTotal and memory forensics using **Volatility** confirmed it to be a **Cobalt Strike/Meterpreter beacon**. It was found running under the guise of a legitimate process name, `spoolsv.exe`, to evade detection.
*   **Persistence Mechanism:** The attacker established persistence by installing the malware as a Windows service named "coreupdater". This was confirmed by analyzing the `SYSTEM` registry hive (`ControlSet001\Services\coreupdater`) in Autopsy, ensuring the malware would survive a reboot.

### Phase 3: Lateral Movement
*   **Objective:** Having compromised the domain controller, the attacker moved to another system on the network to locate valuable data.
*   **Action:** Using the compromised `Administrator` account, the attacker made a successful RDP connection from `DC01` to the workstation `DESKTOP-SDN1RPT`.
*   **Evidence:** This lateral movement was logged as **Event ID 4624** (An account was successfully logged on) in the security event logs of the workstation, timestamped at **2020-09-19 02:36:24 UTC-7**.

### Phase 4: Impact & Data Exfiltration
*   **Data Staging & Access:** Once on the workstation, the attacker accessed a network share `C:\FileShare\Secret`. File system journaling (USN Journal and MFT analysis in Autopsy) shows access to two key files: `Szechuan_Sauce_Recipe.txt` and `Beth_Secret.txt` at **2020-09-19 02:29:39 UTC-7**.
*   **Command & Control (C2):** Network traffic analysis in Wireshark revealed sustained TCP communication from the compromised host to the IP address `203.78.103.109`, a known malicious C2 server. This channel was likely used for data exfiltration.
*   **Anti-Forensics:** The attacker attempted to hide their tracks by performing "time stomping" on the `SECRET_bath.txt` file, altering its timestamps to mislead investigators.

---

## Indicators of Compromise (IoCs)

| Type | Indicator | Description |
| :--- | :--- | :--- |
| **IP Address** | `194.61.24.102` | Attacker IP for RDP brute-force and payload delivery. |
| **IP Address** | `203.78.103.109` | Malicious Command & Control (C2) server. |
| **File Hash (SHA256)** | `(Hash of coreupdater.exe)` | Cobalt Strike/Meterpreter payload. |
| **File Path** | `C:\Windows\System32\coreupdater.exe` | Location of the dropped malware. |
| **Process Name** | `spoolsv.exe` | Malicious process masquerading as a system process. |
| **Registry Key** | `HKLM\SYSTEM\ControlSet001\Services\coreupdater` | Malware persistence as a service. |

---

## Strategic Recommendations
To prevent similar incidents, the following architecture and policy changes are recommended:

| Recommendation | Justification & Business Value | Framework Alignment |
| :--- | :--- | :--- | :--- |
| **Disable External RDP Access** | The initial access vector was a publicly exposed RDP port. Disabling this and requiring access via a secure VPN gateway eliminates this entire attack surface. | **NIST 800-53:** AC-17 <br> **ISO 27001:** A.13.1.1 |
| **Enforce Multi-Factor Authentication (MFA)** | Even with a compromised password, MFA would have prevented the initial successful login, stopping the attack before it began. | **NIST 800-53:** IA-2 <br> **ISO 27001:** A.9.4.3 |
| **Implement Network Segmentation & an IDS** | A properly segmented network would have limited the attacker's ability to move laterally from the DC. An IDS (like Zeek or Snort) would have alerted on the brute-force attempt and C2 traffic. | **NIST 800-53:** SC-7 <br> **ISO 27001:** A.12.4.1, A.13.1.3 |
| **Apply the Principle of Least Privilege** | The use of a domain administrator account for daily tasks enabled trivial lateral movement. Implementing Role-Based Access Control (RBAC) ensures accounts only have the minimum necessary permissions. | **NIST 800-53:** AC-6 <br> **ISO 27001:** A.9.2.3 |
