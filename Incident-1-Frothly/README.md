# Incident 1 - Frothly Insider Investigation
**Wonderland SOC | Cisco NetAcad Cybersecurity Defense Analyst | Course 5**
Analyst: Elizabeth Watt | Platform: Splunk Blue Team Academy

---

## Overview

Wonderland SOC was asked to look into potential insider threat activity at Frothly, operating out of the Thirsty Berner Brew Supply facility. The investigation covered three areas: physical badge access, remote authentication, and endpoint file system activity. What looked like separate issues ended up being connected.

---

## Finding 1.1.a - Physical Security Audit

Pulled badge logs for the Thirsty Berner Brew Supply location and filtered for activity around the supply room.

Three people came up:

- **Mateo** (Head Brewer) – accessed the supply room repeatedly during inventory periods. Confirmed to be stealing supplies.
- **Richard Schlitzer** (Sales Manager) - badge showed supply room access, but Richard is a hybrid employee not assigned to that location.
- **Nathaniel** (Intern, Richard's nephew) - attempted supply room access but was denied. His badge wasn't programmed for that reader.

Mateo's access pattern was the clearest anomaly from the physical data. Richard and Nathaniel showing up at the same location added early context for what came next.

---

## Finding 1.1.b - Chasing Remote Access

Investigated Richard Schlitzer's VPN and Salesforce login activity. Used `iplocation` to map source IPs to physical locations, then compared both data sources side by side.

Richard was in Tijuana. Someone was logging into his Salesforce account from the U.S. at the same time, a clear geographic impossibility for a single user. That someone was Nathaniel, using Richard's credentials while he was out of the country.

The main challenge here was that VPN logs (`cp_log`) and Salesforce streaming events use different field names for the same data. Used `coalesce` to normalize `src`/`SourceIp` and `user`/`Username` into unified fields so both sources could be viewed together in one timeline.

---

## Finding 1.1.c - Alarming File System Activity

Searched DTEX endpoint telemetry for file system activity and filtered by the `.lockbit` extension.

LockBit ransomware was identified on `FROTHLY\richschlitzer` — Richard's workstation. At the time of discovery it was isolated to his machine. Escalated immediately for containment before it could spread.

---

## How It Connected

Going in, these looked like three separate issues. By the end they weren't.

Mateo had been stealing physical supplies and was colluding with Nathaniel on something broader. Nathaniel, meanwhile, had been using Richard's Salesforce credentials while Richard was traveling. Richard wasn't doing anything wrong, his account was being misused and his workstation had ransomware on it. He was more of a victim than a suspect.

Physical theft, credential misuse, and ransomware - all in the same investigation, all loosely tied together through Nathaniel.

---

## Outcome

Findings were handed off to Grace, Frothly's IR lead. Her team confirmed the insider threat activity. Mateo and Nathaniel were both implicated. Richard's host went through containment and recovery.

Frothly is now implementing:
- **UBA (User Behavior Analytics)** - to catch behavioral anomalies earlier, like Mateo's access spikes
- **DLP (Data Loss Prevention)** - to monitor and restrict unauthorized data access and movement

---

## Indicators of Interest

- `richard@yellowtalon.co` / VPN alias `richards` - Richard Schlitzer (victim)
- Nathaniel - intern, Richard's nephew (credential misuse, collusion)
- Mateo - Head Brewer (physical theft, collusion)
- `FROTHLY\richschlitzer` - Richard's workstation (LockBit ransomware)

---

## MITRE ATT&CK

- **T1078: Valid Accounts** - Nathaniel using Richard's credentials without authorization
- **T1486: Data Encrypted for Impact** - LockBit ransomware on Richard's host

---

## SPL Queries

### 1.1.a - Physical Security Audit

```spl
`All badge activity at Thirsty Berner locations`
index=main sourcetype=st_frothly_events reader_desc="THIRSTY*"
| stats count by reader_desc employee_first_name employee_job_title

`Granted access at the supply room over time`
index=main sourcetype=st_frothly_events reader_desc="THIRSTY_BERNER BREW SUPPLY"
  event_desc="Access Granted" employee_first_name="*"
| timechart count by employee_first_name limit=10

`Denied access attempts at the supply room`
index=main sourcetype=st_frothly_events
  event_desc="Access Denied Unauthorized Entry Level"
  OR event_desc="Access Denied Unauthorized Time"
  reader_desc="THIRSTY_BERNER BREW SUPPLY"
| stats count by reader_desc, employee_first_name employee_job_title
```

---

### 1.1.b - Chasing Remote Access

```spl
`Basic VPN search for Richard`
index=main sourcetype="cp_log" user=richards

`VPN logins with geolocation`
index=main sourcetype="cp_log" user="richards"
| iplocation src
| where City!=""
| table src City Region Country lat long _time
| dedup src
| sort _time

`Salesforce logins with geolocation`
index=main source="sfdc_streaming_api_events://login_events"
  Username="richard@yellowtalon.co"
| iplocation src
| where City!=""
| table _time Username SourceIp City
| dedup _time
| sort -_time

`Combined VPN + Salesforce on a geo map`
index=main (sourcetype="cp_log" OR source="sfdc_streaming_api_events:///login_events")
  (user=Richards OR Username="richard@yellowtalon.com")
| iplocation src
| where City!=""
| geostats count by City latfield=lat longfield=lon

`Full correlated login timeline across both sources`
index=main (source="sfdc_streaming_api_events://login_events" OR sourcetype="cp_log")
  (Username="richard@yellowtalon.co" OR user=richards)
| eval src=coalesce(src, SourceIp)
| eval user=coalesce(Username, user)
| iplocation src
| eval State=coalesce(Region, Subdivision)
| where City!=""
| table _time user src City State Country
| dedup _time
| sort -_time
```

---

### 1.1.c - Alarming File System Activity

```spl
`General file system activity`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity

`Filter for lockbit extension`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity
  Source_File_Extension=lockbit
| stats values(Activity_Details)

`Identify affected devices`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity
  Source_File_Extension=lockbit
| stats count by Device_Name
```

---

*Wonderland SOC | Splunk Blue Team Academy | Cisco NetAcad Cybersecurity Defense Analyst | Course 5*


