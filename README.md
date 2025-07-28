# Project Title
Digital Forensics Investigation: The Stolen Szechuan Sauce Case



## Case Summary
- **Objective:** To conduct a full-scale digital forensics and incident response investigation into a data breach involving the theft of proprietary intellectual property. My goal was to analyze a complex set of digital evidence to identify the attacker's TTPs, trace the full attack lifecycle, and provide actionable recommendations to prevent future incidents.
- **Scope:** The investigation covered a full set of evidence from a simulated corporate network, including `.E01` disk images of a domain controller (DC01) and a desktop (DESKTOP-SDN1RPT), a full packet capture (`.pcap`), and memory dumps (`.vmem`) from the compromised systems.
- **Tools Used:** Autopsy, Wireshark, FTK Imager, Volatility, Python, VirusTotal.
- **Outcome:** I successfully reconstructed the entire attack chain, from the initial RDP brute-force entry to the lateral movement and final data exfiltration. I identified the Cobalt Strike malware used, pinpointed the stolen files, and developed a set of strategic recommendations aligned with NIST and ISO frameworks to harden the organization's security posture.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Autopsy** | Core forensic analysis of disk images, including timeline generation, registry parsing, and file system review. |
| **Wireshark** | Deep-dive analysis of network traffic to identify initial access and C2 communication. |
| **Volatility 3** | Memory forensics to identify malicious processes (Meterpreter/Cobalt Strike) that were hidden on disk. |
| **FTK Imager** | Evidence mounting and extraction of file system metadata (MFT, USN Journal). |
| **Python** | Used for ad-hoc scripting, such as log parsing and hash analysis. |
| **VirusTotal** | Validated maliciousness of identified IP addresses and file hashes. |
| **OS/VM Used** | Isolated SANS SIFT Workstation VM for safe and effective analysis of all evidence. |



## Case Background
This investigation was based on the DFIR Madness "Stolen Szechuan Sauce" CTF. The scenario began when a highly sensitive and proprietary recipe file was discovered for sale on the dark web. I was brought in as the lead DFIR analyst to investigate the breach. I was provided with a complete set of forensic artifacts from the suspected systems and network, and my mission was to perform a root cause analysis, determine the full scope of the compromise, and provide a detailed report for both technical and leadership audiences.



## Methodology
My investigation followed a rigorous and structured DFIR process to ensure all evidence was accurately correlated.

1.  **Initial Triage & Evidence Review:** I began by ingesting the disk images into Autopsy to perform an initial analysis of the systems involved. This included identifying the operating systems, user accounts, and basic system configurations.
2.  **Network Traffic Analysis:** I loaded the PCAP file into Wireshark and immediately began filtering for common initial access vectors. I focused on RDP traffic, which quickly revealed a high volume of failed logins characteristic of a brute-force attack.
3.  **Memory Forensics:** To understand the live state of the systems during the attack, I ran the memory dumps through Volatility. Using the `pslist` plugin, I identified suspicious processes that were masquerading as legitimate system files, leading me to the core malware payload.
4.  **Filesystem Analysis:** With initial indicators from memory and network analysis, I returned to Autopsy to perform a deep dive on the file system. I used the MFT and USN Journal to create a super-timeline, allowing me to trace the creation, movement, and execution of the malware on disk.
5.  **Artifact Correlation:** I systematically correlated findings across all evidence sources. For example, I linked the RDP source IP from Wireshark to the successful login event (ID 4624) in the Windows Event Logs parsed by Autopsy, and then to the malware drop that occurred minutes later.
6.  **Reporting and Recommendations:** After answering all investigative questions and building a complete attack narrative, I mapped the attacker's TTPs to the MITRE ATT&CK framework and developed a set of strategic recommendations aligned with NIST and ISO 27001.



## Findings & Evidence
The investigation uncovered a multi-stage attack that led to the successful exfiltration of sensitive company data.

The attacker gained initial access by brute-forcing an RDP password for the Administrator account on the domain controller (DC01). Once inside, they downloaded and executed a Cobalt Strike payload (`coreupdater.exe`), which they used to establish persistence and a C2 channel. From the DC, they moved laterally to a desktop machine, accessed a file share, and exfiltrated the target files.

| Artifact Type | Location / Value | Finding |
| :--- | :--- | :--- |
| **Initial Access** | IP: `194.61.24.102` | This IP conducted a successful RDP brute-force attack (MITRE T1110.001) against the DC on 2020-09-19. |
| **Malware on Disk** | `C:\Windows\System32\coreupdater.exe` | Cobalt Strike beacon, dropped initially in the Downloads folder and moved to `System32` to evade detection. |
| **Malicious Process** | `spoolsv.exe` (in memory) | The Cobalt Strike beacon was injected into a legitimate-looking process to hide its execution (MITRE T1055). |
| **C2 Server** | IP: `203.78.103.109` | The malware established a persistent TCP connection to this IP for command and control. VirusTotal confirmed it was malicious. |
| **Persistence** | Registry: `ControlSet001\Services\coreupdater` | The malware was installed as a system service to ensure it would survive a system reboot (MITRE T1543.003). |
| **Lateral Movement** | Event Log ID 4624 (DESKTOP-SDN1RPT) | The attacker used the compromised Administrator account to RDP from the DC to the desktop machine. |
| **Data Exfiltration** | File Access: `C:\FileShare\Secret\` | The attacker accessed the "Szechuan sauce recipe" and "Beth_Secret.txt" files on 2020-09-19 at 02:29 UTC-7. |



## Conclusion
The investigation definitively concluded that the Szechuan sauce recipe was stolen by an external attacker. The root cause of the breach was a publicly exposed RDP port secured with a weak password, which allowed the attacker to brute-force their way into the network.

**Impact:** The compromise resulted in the theft of critical intellectual property, a full compromise of the domain controller and a user workstation, and a demonstrated inability to detect or prevent a common cyberattack.

**Recommendations:**
1.  **Immediate Containment:** Disable all public-facing RDP access immediately. If remote access is required, it must be placed behind a VPN with Multi-Factor Authentication (MFA). (NIST AC-17, IA-2)
2.  **Architectural Hardening:** Implement network segmentation to prevent lateral movement from critical servers to user workstations. Deploy a Network Intrusion Detection System (IDS/IPS) to monitor for suspicious traffic patterns. (ISO A.13.1.3, A.12.4.1)
3.  **Access Control:** Enforce the Principle of Least Privilege using Role-Based Access Control (RBAC). The "Administrator" account should not be used for daily operations or lateral movement. (NIST AC-6)
4.  **Endpoint Security:** Deploy a modern EDR solution capable of detecting advanced threats like Cobalt Strike through behavioral analysis, not just file signatures. (NIST DE.CM-1)



## Lessons Learned / Reflection
This project was an incredible simulation of a real-world investigation, reinforcing the critical importance of correlating data from disparate sources. While analyzing the disk image was valuable, the full picture only emerged when I integrated findings from the network traffic and memory dump. For example, memory analysis revealed the malicious process that was invisible on the disk, and the network analysis provided the attacker's entry point and C2 destination.

This exercise highlighted that mastering a single tool is not enough; a successful DFIR analyst must be able to pivot between different types of evidence and analysis techniques to build a complete and defensible timeline of events.



## References
- [The MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS DFIR Cheat Sheets & Posters](https://www.sans.org/posters/dfir/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/en/latest/)


#DFIR #IncidentResponse #DigitalForensics #Cybersecurity #Autopsy #Wireshark #Volatility #ThreatHunting #BlueTeam
