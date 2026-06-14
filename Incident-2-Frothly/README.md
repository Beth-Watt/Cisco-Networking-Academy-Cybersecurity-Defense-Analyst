# Incident 2 - Brute Force Access Behavior Detected
**Wonderland SOC | Cisco NetAcad Cybersecurity Defense Analyst | Course 5**
Analyst: Elizabeth Watt | Platform: Splunk Blue Team Academy

---

## Overview

Alert fired for brute force activity from `172.16.16.245`, an IP outside the company's `192.168.x.x` range. Started broad and narrowed down from there.

---

## Investigation

First SPL returned two sourcetypes for that IP: `WinEventLog` and `fgt_event`.

- `WinEventLog` - Windows Security events, has the authentication data that triggered the alert
- `fgt_event` - Fortigate firewall logs, showed tunnel creation and shutdown, this is how I knew the IP was coming in through a VPN

The system had **2,609 failed authentications and 2 successful logins** in the last hour. Four devices were targeted: DBell, PPark, JSam, and Main Inv.

After checking with the Splunk team it turned out this is a partner VPN, allows connectivity to select services for a company that sells the T-shirt Co. product internationally. That explained the IP, but not the volume of failed attempts, so I kept digging.

Searched `WinEventLog:Security` for interesting fields and confirmed the brute force. As a new analyst I flagged this for a more experienced analyst to help decide whether to escalate immediately or gather more data first. The IR group decided to block the connection while we continued.

Searched HTTP stream data for Main-Inv and found a `.bin` file downloaded from `13.107.4.50`, threat intel shows that IP is associated with malware and trojans. Possible Clop malware variant. No machine logs available to go further.

---

## Final Analysis

- Suspicious activity triggered the Brute Force Activity Detected rule - tied to Credential Access and Discovery MITRE tactics
- Source IP `172.16.16.245` is a partner VPN connection used for international sales
- 2,609 failed auth attempts across 4 devices, 2 successful logins confirmed
- `tshirt_admin` is the compromised account - `WeSellTshirts` is the partner VPN account
- DBell and Main-Inv confirmed compromised
- `13.107.4.50` flagged by threat intel - `.bin` download on Main-Inv is a possible Clop malware variant
- Brute force attack confirmed

---

## Indicators of Interest

- `172.16.16.245` - VPN tunnel IP, source of brute force
- `13.107.4.50` - malicious file download source
- `tshirt_admin` - compromised account
- `WeSellTshirts` - partner VPN account
- `DBell` - `192.168.16.34` - Windows Desktop, compromised
- `Main-Inv` - `192.168.55.3` - Windows Server, compromised
- `PPark`, `JSam` - targeted, not confirmed compromised

---

## MITRE ATT&CK

- **T1110: Brute Force** / Credential Access
- **T1201: Password Policy Discovery** / Discovery
- **TA0001: Initial Access**
- **TA0006: Credential Access**

---

## SPL Queries

```spl
`1. General search — see which sourcetypes have data on the IP`
index=* 172.16.16.245
| stats count by sourcetype

`2. Fortigate firewall logs`
index=* 172.16.16.245 sourcetype=fgt_event

`3. Wide search for the IP`
index=* 172.16.16.245

`4. Narrow to authentication events`
index=* tag=authentication 172.16.16.245
| stats count by sourcetype, source

`5. WinEventLog data for the IP`
index=* 172.16.16.245 sourcetype=WinEventLog

`6. Successful logins only (EventCode 4624)`
index=* 172.16.16.245 sourcetype=WinEventLog "EventCode=4624"

`7. HTTP stream data for Main-Inv`
index=bta-ts sourcetype="stream:http" (host=Main-inv OR src_ip=192.168.55.3)
```

---

*Wonderland SOC | Splunk Blue Team Academy | Cisco NetAcad Cybersecurity Defense Analyst | Course 5*
