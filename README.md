# Cisco Networking Academy Cybersecurity Defense Analyst
Splunk Blue Team Academy: labs and incident investigation reports_Wonderland SOC

**Platform:** Cisco Networking Academy / Splunk Blue Team Academy  
**Duration:** 30 hours | 7 courses + final exam  
**Status:**   Completed
**Course link:** [netacad.com](https://www.netacad.com/career-paths/splunk-cybersecurity-defense-analyst)

---

## About

This is a free career path offered by Cisco Networking Academy and Splunk. It's built around hands-on SOC analyst training: learning to search and investigate security data, work inside Splunk Enterprise Security, and develop the habits of a Tier 1 analyst. The whole path takes place inside the fictional Wonderland SOC, which is the same environment used in the incident labs documented in this repo.

The path leads to the Splunk Certified Cybersecurity Defense Analyst exam.

---

## Courses

1. **The Cybersecurity Landscape** - risk management, threat analysis, SOC fundamentals
2. **Understanding Threats and Attacks** - threat types, MITRE ATT&CK framework
3. **Security Operations and the Defense Analyst** - SOC operations, analyst roles, defense metrics
4. **Data and Tools for Defense Analysts** - threat intelligence, Splunk ES, SPL best practices, CIM and data models
5. **The Art of Investigation** - investigation methodology, working notable events
6. **SOC Essentials: Investigating with Splunk** - hands-on Splunk ES, risk-based alerting, SOAR
7. **SOC Essentials: Introduction to Threat Hunting** - PEAK framework, hypothesis-driven hunting, outlier detection

---

## Labs - Frothly Incident Investigations

The hands-on portion of the course involved working real simulated incidents inside the Wonderland SOC. All three are documented in this repo.

**Incident 1 - Frothly Insider Threat**
Physical badge access anomalies led to an investigation involving credential misuse and LockBit ransomware. Three people came up: Mateo (supply theft), Nathaniel (using Richard Schlitzer's Salesforce credentials while Richard was out of the country), and Richard (victim - his workstation had ransomware on it). Used `coalesce` to normalize field names across VPN and Salesforce log sources and map logins geographically. Confirmed true positive, handed off to IR.

**Incident 2 - Brute Force Access Behavior Detected**
Alert fired for brute force activity from `172.16.16.245` — an IP outside the company's `192.168.x.x` range. Two sourcetypes came back: `WinEventLog` (authentication data that triggered the alert) and `fgt_event` (Fortigate firewall logs showing VPN tunnel creation — that's how the external IP made sense). The system had 2,609 failed authentications and 2 successful logins in the last hour across four targeted devices: DBell, PPark, JSam, and Main-Inv. Checked with the Splunk team and confirmed it was a partner VPN used for international sales, that explained the IP but not the volume. Kept digging. As a new analyst I flagged it for a more experienced analyst before deciding whether to escalate. IR blocked the connection while the investigation continued. Found a `.bin` file downloaded on Main-Inv from `13.107.4.50`, threat intel flagged that IP as associated with malware and trojans, possible Clop variant. No machine logs available to go further. DBell and Main-Inv confirmed compromised. Brute force confirmed true positive.

**Incident 3 - Creation of Shadow Copy**
High-urgency alert for `vssadmin.exe` on Frothly's Active Directory Server. The shadow copy was deleted minutes after creation, a pattern consistent with credential dumping. Traced it back to a malicious JavaScript file (`hefeweizen_tips.js`) delivered via a suspicious Azure CDN domain and executed through the Windows Print Spooler service. Remote PowerShell pointed to lateral movement. Account `pcerf` appeared in logs but wasn't the actor. Confirmed true positive with Frothly IT.

---

## Tools & Concepts Used

- Splunk (SPL, `tstats`, `coalesce`, `iplocation`, `geostats`, data models)
- Splunk Enterprise Security - notable events, risk-based alerting
- DTEX endpoint telemetry
- MITRE ATT&CK framework
- Physical badge/access log analysis
- DNS, VPN, and Salesforce streaming log correlation

---

*Wonderland SOC | Splunk Blue Team Academy | Cisco NetAcad Cybersecurity Defense Analyst*
