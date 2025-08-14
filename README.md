# Digital Forensics Investigation: The Stolen Szechuan Sauce Case


## Case Summary
- **Objective:** To conduct a full-scale digital forensics and incident response investigation into a data breach involving the theft of proprietary intellectual property. My goal was to analyze a complex set of digital evidence to identify the attacker's TTPs, trace the full attack lifecycle, and provide actionable recommendations to prevent future incidents.
- **Scope:** The investigation covered a full set of evidence from a simulated corporate network, including `.E01` disk images of a domain controller (DC01) and a desktop (DESKTOP-SDN1RPT), a full packet capture (`.pcap`), and memory dumps (`.vmem`) from the compromised systems.
- **Tools Used:** Autopsy, Wireshark, Volatility, Registry Explorer, VirusTotal, AbuseIPDB.
- **Outcome:** I successfully reconstructed the entire attack chain, from the initial RDP brute-force entry to the lateral movement and final data exfiltration. I identified the Cobalt Strike/Metasploit malware used, pinpointed the stolen files, and developed a set of strategic recommendations aligned with NIST and ISO frameworks to harden the organization's security posture.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Autopsy** | Core forensic analysis of disk images, including timeline generation, registry parsing, and file system review. |
| **Wireshark** | Deep-dive analysis of network traffic to identify the initial brute-force attack and the malware C2 communication. |
| **Volatility / Registry Explorer** | Memory forensics and registry analysis to identify malicious processes and persistence mechanisms. |
| **VirusTotal / AbuseIPDB** | OSINT tools used to verify the maliciousness of identified IP addresses and file hashes. |
| **OS/VM Used** | Windows Server 2012 R2, Windows 10 (Targets) / Kali Linux SIFT Workstation (Analysis). |



## Case Background
This investigation was based on the DFIR Madness "Stolen Szechuan Sauce" CTF. The scenario began when a highly sensitive and proprietary recipe file was discovered for sale on the dark web. I was brought in as the lead DFIR analyst to investigate the breach. I was provided with a complete set of forensic artifacts from the suspected systems and network, and my mission was to perform a root cause analysis, determine the full scope of the compromise, and provide a detailed report for both technical and leadership audiences.



## Methodology
My investigation followed a rigorous and structured DFIR process to ensure all evidence was accurately correlated.

1.  **Initial Triage & Evidence Review:** I began by ingesting the disk images into Autopsy to perform an initial analysis of the systems involved. This included identifying the operating systems (Windows Server 2012 R2, Windows 10), user accounts, and basic system configurations.
2.  **Network Traffic Analysis:** I loaded the PCAP file into Wireshark and immediately began filtering for common initial access vectors. I focused on RDP traffic from the attacker's IP (`194.61.24.102`), which revealed a high volume of failed logins characteristic of a brute-force attack.
3.  **Malware Identification & Analysis:** Using Wireshark's "Export Objects" feature, I extracted a suspicious executable (`coreupdater.exe`) downloaded via HTTP. I cross-referenced its MD5 hash in VirusTotal, which confirmed it as a Trojan/Metasploit payload.
4.  **Deep-Dive Filesystem & Persistence Analysis:** With the malware identified, I returned to Autopsy and Registry Explorer. I found the malware on disk in `C:\Windows\System32\` and located the registry key (`ControlSet001\Services\coreupdater`) that the attacker created to establish persistence as a service.
5.  **Reconstructing Lateral Movement & Data Access:** I correlated successful logon events (Event ID 4624) from the Windows Event Logs with TCP streams in Wireshark. This proved the attacker used the compromised `Administrator` account to RDP from the Domain Controller to a desktop, where they accessed files in the `C:\FileShare\Secret` directory.



## Findings 
The investigation uncovered a multi-stage attack that led to the successful exfiltration of sensitive company data.

The attacker gained initial access by brute-forcing the RDP password for the `Administrator` account on the domain controller (DC01). Once inside, they downloaded and executed a Trojan (`coreupdater.exe`), which they used to establish persistence and a C2 channel. From the DC, they moved laterally to a desktop machine, accessed a file share, and exfiltrated the target files.

| Artifact Type | Location / Value | Finding |
| :--- | :--- | :--- |
| **Initial Access** | IP: `194.61.24.102` | This IP conducted a successful RDP brute-force attack (MITRE T1110.001) against the DC on 2020-09-19. |
| **Malware on Disk** | `C:\Windows\System32\coreupdater.exe` | The Trojan payload, initially downloaded to the user's Downloads folder, was moved to `System32` to evade detection. |
| **C2 Server** | IP: `203.78.103.109` | The malware established a persistent TCP connection to this IP for command and control. VirusTotal flagged this IP as malicious. |
| **Persistence** | Registry: `HKLM\SYSTEM\ControlSet001\Services\coreupdater` | The malware was installed as a system service to ensure it would run automatically on system startup (MITRE T1543.003). |
| **Lateral Movement** | Event Log ID 4624 (on DESKTOP-SDN1RPT) | The attacker used the compromised `Administrator` account to RDP from the DC to the desktop machine on 2020-09-19 at 02:36 UTC. |
| **Data Exfiltration** | File Access: `C:\FileShare\Secret\` | The attacker accessed the "Szechuan sauce recipe" and "Beth_Secret.txt" files on 2020-09-19 around 06:35 EAT. |

---


## Conclusion
The investigation definitively concluded that the "Szechuan Sauce" recipe was stolen by an external attacker. The root cause of the breach was a publicly exposed RDP port secured with a weak password, which allowed the attacker to brute-force their way into the network.

**Impact:** The compromise resulted in the theft of critical intellectual property, a full compromise of the domain controller and a user workstation, and a demonstrated inability to detect or prevent a common cyberattack.

**Recommendations:**
1.  **Immediate Containment:** Disable all public-facing RDP access immediately. If remote access is required, it must be placed behind a VPN with Multi-Factor Authentication (MFA). (NIST AC-17, IA-2)
2.  **Architectural Hardening:** Implement network segmentation to prevent lateral movement from critical servers to user workstations. Deploy a Network Intrusion Detection System (IDS/IPS) to monitor for suspicious traffic patterns. (ISO A.13.1.3, A.12.4.1)
3.  **Access Control:** Enforce the Principle of Least Privilege using Role-Based Access Control (RBAC). The `Administrator` account should not be used for daily operations or lateral movement. (NIST AC-6)
4.  **Endpoint Security:** Deploy a modern EDR solution capable of detecting advanced threats like Cobalt Strike and Metasploit through behavioral analysis, not just file signatures. (NIST DE.CM-1)



## Lessons Learned / Reflection
This investigation was a powerful, hands-on demonstration of the entire DFIR lifecycle. The key takeaway was the critical importance of **correlating data from disparate sources.** While analyzing the disk image in Autopsy was valuable, the full picture only emerged when I integrated findings from the network traffic and registry analysis. For example:
-   **Wireshark** gave me the initial entry vector (RDP brute-force).
-   **Autopsy** showed me *what* was stolen and *when*.
-   **Registry Explorer** revealed *how* the attacker maintained their foothold.

This exercise proves that a successful DFIR analyst must be able to pivot seamlessly between different types of evidence and analysis techniques to build a complete and defensible timeline of events.



## References
- [DFIR Madness - Case 001](https://dfirmadness.com/case001)
- [The MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS DFIR Cheat Sheets & Posters](https://www.sans.org/posters/dfir/)
