# Forensics Analysis: The Stolen Szechuan Sauce

## Overview
This project simulates a digital forensics investigation into the theft of a proprietary "Szechuan Sauce" recipe, inspired by the DFIR Madness CTF challenge. As a Blue Team analyst, I analyzed disk images, memory dumps, and network traffic to trace the attacker’s actions, identify malware, and recommend mitigations. Using tools like Autopsy, Wireshark, FTK Imager, and Python, I answered 14 investigative questions, mapping threats to MITRE ATT&CK and aligning recommendations with NIST 800-53 and ISO 27001. This project showcases my skills in Digital Forensics and Incident Response (DFIR), Security Operations Center (SOC) operations, Threat Intelligence, and Governance, Risk, and Compliance (GRC).

**Date**: September 2024

**Analyst**: Dorathy Christopher

## Introduction
Inspired by the "Rick and Morty" themed DFIR Madness challenge, this project investigates the theft of a Szechuan sauce recipe found on the dark web. By analyzing digital artifacts (disk images, PCAPs, memory dumps), I traced the attacker’s entry vector, malware deployment, and data exfiltration, demonstrating real-world DFIR techniques to solve cybercrimes.

## Objectives

- Simulate a real-world DFIR investigation to track a data breach.
- Analyze digital artifacts (logs, registry hives, network traffic, metadata).
- Identify the perpetrator, attack methods, and stolen data.
- Recommend architecture and policy improvements to prevent future breaches.

## Tools and Technologies

**Autopsy**: Analyzed disk images (E01 files) for file system artifacts, registry hives, and deleted files.

**Wireshark**: Examined PCAP files for network traffic, identifying RDP brute-forcing and malware communication.

**FTK Imager**: Created forensic images and extracted file metadata (e.g., MFT, USN journal).

**Python**: Scripted log parsing and hash calculations for malware analysis.

**Volatility**: Conducted memory forensics to identify malicious processes.

**VirusTotal**: Validated malicious IPs and file hashes.

## Investigative Questions and Findings
The investigation answered 14 key questions to uncover the breach details:

- **Operating System of the Server**: Windows Server 2012 R2 Standard Evaluation (parsed via Autopsy from SOFTWARE hive: C:\Windows\System32\config\SOFTWARE\Microsoft\Windows NT\CurrentVersion).
- **Operating System of the Desktop**: Windows 10 Enterprise, build 19041 (identified via Autopsy’s OS Information module).
- **Local Time of the Server**: Pacific Standard Time (UTC-7), misconfigured on the domain controller (verified via SYSTEM hive in Autopsy and NTP packets in Wireshark).
- **Was There a Breach?**: Yes, unauthorized access occurred via RDP brute-forcing (Event ID 4625 logs analyzed in Autopsy).
- **Initial Entry Vector**: RDP brute-force attack from IP 194.61.24.102 targeting port 3389 on 2020-09-19 02:19:13 UTC-7 (Wireshark filter: rdp && ip.src == 194.61.24.102).

### Malware Usage:
**Malicious Process**: spoolsv.exe (Meterpreter payload, identified via Volatility’s pslist plugin).

**IP Delivering Payload**: 194.61.24.102 (delivered coreupdater.exe via HTTP, Wireshark HTTP export).

**Malware C2 IP**: 203.78.103.109 (TCP connection in Wireshark, flagged in VirusTotal).

**Malware Location**: C:\Windows\System32\coreupdater.exe (originally in Downloads folder, moved per MFT in Autopsy).

**First Appearance**: 2020-09-19 02:24:12 UTC (MFT and USN journal in Autopsy).

**Moved?**: Yes, from Downloads to System32 (USN journal parent entry 84880).

**Capabilities**: Data exfiltration, persistence via registry (Meterpreter framework, VirusTotal flagged as Cobalt Strike).

**Easily Obtained?**: Yes, built on Cobalt Strike, widely available on dark web.

**Persistence?**: Yes, installed as a service (ControlSet001\Services\coreupdater) on DC01 (2020-09-19 03:27:49 UTC-6) and DESKTOP-SDN1RPT (2020-09-19 03:44:42 UTC-6).


**Malicious IPs**: 194.61.24.102 (RDP brute-force, payload delivery), 203.78.103.109 (C2 communication). Both flagged as malicious in VirusTotal.

**Adversary Infrastructure**: 194.61.24.102 linked to RDP brute-force campaigns (OSINT via VirusTotal). Insufficient data on other attacks at the time.

**Other Systems Accessed**: Yes, lateral movement from DC01 to DESKTOP-SDN1RPT via compromised Administrator account on 2020-09-19 02:36:24 UTC-7 (Event ID 4624, Autopsy Security.evtx).

**Data Stolen/Accessed**: Yes, Szechuan sauce recipe and Beth_Secret.txt accessed from C:\FileShare\Secret on 2020-09-19 02:29:39 UTC-7 (Autopsy UsrClass.dat).

**Network Layout**: Two systems (DC01: 10.42.85.10, DESKTOP-SDN1RPT) connected via internal network, externally accessible via RDP (Autopsy Tcpip Parameters).

## Architecture Changes:
- Disable external RDP access (NIST 800-53 AC-17).
- Implement MFA for all accounts (NIST 800-53 IA-2).
- Deploy Network Intrusion Detection System (e.g., Zeek) (ISO 27001 A.12.4.1).
- Enforce least privilege via RBAC (NIST 800-53 AC-6).


**Szechuan Sauce Theft**: Stolen on 2020-09-19 02:29:39 UTC-7 (Autopsy file access logs).

**Other Sensitive Files**: Beth_Secret.txt accessed on 2020-09-19 02:29:39 UTC-7; SECRET_bath.txt showed time stomping (Autopsy metadata).

**Last Known Contact**: 2020-09-19 02:57:00 UTC (Wireshark TCP traffic to 203.78.103.109).

## Conclusion
This project demonstrates a comprehensive DFIR investigation, tracing an RDP brute-force attack, Cobalt Strike malware deployment, and data exfiltration. By leveraging Autopsy, Wireshark, FTK Imager, Volatility, and Python, I identified the attacker’s tactics (MITRE ATT&CK T1190, T1486) and recommended NIST-aligned mitigations. The investigation highlights the critical role of digital forensics in uncovering cybercrimes and strengthening defenses.
