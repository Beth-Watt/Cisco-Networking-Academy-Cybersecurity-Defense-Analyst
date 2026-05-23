Incident 1 – Frothly Insider Investigation
Wonderland SOC | Cisco NetAcad Cybersecurity Defense Analyst – Course 5
Analyst: Elizabeth Watt | Platform: Splunk Blue Team Academy

What We Were Looking At
Frothly (Thirsty Berner Brew Supply) flagged some anomalies and brought in Wonderland SOC to take a look. The investigation broke down into three areas — physical badge access, remote logins, and endpoint file activity. They looked unrelated at first. They weren't.

1.1.a – Physical Security Audit
We pulled badge logs for the Thirsty Berner Brew Supply location and looked for anything weird around the supply room.
Three people stood out:

Mateo (Head Brewer) – kept accessing the supply room way more than expected, specifically during inventory periods. Turned out he was unhappy and had been stealing supplies.
Richard Schlitzer – his badge showed access to the supply room, but Richard is a hybrid Sales Manager and isn't even assigned to that location.
Nathaniel – Richard's nephew, new intern. Tried to get into the supply room but his badge wasn't programmed for it, so access was denied. Still showed up in the logs though.

SPL for this section:
spl`All badge activity at Thirsty Berner locations`
index=main sourcetype=st_frothly_events reader_desc="THIRSTY*"
| stats count by reader_desc employee_first_name employee_job_title

`Who got into the supply room and when`
index=main sourcetype=st_frothly_events reader_desc="THIRSTY_BERNER BREW SUPPLY"
  event_desc="Access Granted" employee_first_name="*"
| timechart count by employee_first_name limit=10

`Denied access attempts`
index=main sourcetype=st_frothly_events
  event_desc="Access Denied Unauthorized Entry Level"
  OR event_desc="Access Denied Unauthorized Time"
  reader_desc="THIRSTY_BERNER BREW SUPPLY"
| stats count by reader_desc, employee_first_name employee_job_title
timechart count by is useful here because it groups events into time buckets so you can actually see the spikes in Mateo's access pattern visually rather than just as a raw count.

1.1.b – Chasing Remote Access
Richard's VPN and Salesforce login data looked off. We used iplocation to map login source IPs to physical locations and compared the two data sources.
Richard was in Tijuana. But someone was logging into his Salesforce account from the U.S. at the same time. That's your red flag right there — simultaneous logins from two countries.
That someone was Nathaniel. He was using Richard's credentials while Richard was out of the country.
The key to this section was combining the VPN logs (cp_log) and Salesforce streaming API events into one view using coalesce to normalize the fields across both sources, since they use different field names for the same data.
spl`Basic VPN search for Richard`
index=main sourcetype="cp_log" user=richards

`VPN logins with geo enrichment`
index=main sourcetype="cp_log" user="richards"
| iplocation src
| where City!=""
| table src City Region Country lat long _time
| dedup src
| sort _time

`Salesforce logins with geo enrichment`
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

`Full correlated timeline across both sources`
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
coalesce is doing the heavy lifting in that last query — the VPN logs use src and user while Salesforce uses SourceIp and Username, so without normalizing those you'd be missing half the picture.

1.1.c – Alarming File System Activity
This one came from DTEX endpoint telemetry. We searched file system activity and filtered for the .lockbit extension.
LockBit ransomware was sitting on FROTHLY\richschlitzer — Richard's workstation.
spl`General file system activity`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity

`Filter for lockbit extension`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity
  Source_File_Extension=lockbit
| stats values(Activity_Details)

`Which device`
index=dtex sourcetype=dtex_st_activities Activity_Group=FileSystemActivity
  Source_File_Extension=lockbit
| stats count by Device_Name
At the time it was isolated to his machine. We escalated immediately to get containment going before it could spread.

How It All Came Together
Going in, these three threads looked like separate issues. By the end they weren't:
Mateo was stealing physical supplies and had recruited Nathaniel (the intern) into whatever he was doing. Nathaniel meanwhile had been using Richard's Salesforce credentials while Richard was traveling, which is what made Richard's login data look so suspicious. Richard himself wasn't doing anything wrong — his account was being misused and his workstation had ransomware on it, making him more of a victim than a suspect.
So you had physical theft, credential misuse, and ransomware all showing up in the same investigation, all loosely connected through Nathaniel.

What Happened After
We handed everything off to Grace (Frothly's IR lead) and her team confirmed the insider threat activity. Mateo and Nathaniel were both implicated. Richard's host went through containment and recovery.
Going forward, Frothly is implementing:

UBA (User Behavior Analytics) to catch behavioral anomalies earlier — things like Mateo's access spikes would get flagged automatically
DLP (Data Loss Prevention) to add another layer around unauthorized data access and movement


Users / Hosts Involved

richard@yellowtalon.co / VPN alias richards — Richard Schlitzer, Sales Manager (victim)
Nathaniel — intern, Richard's nephew (credential misuse)
Mateo — Head Brewer (physical theft, collusion)
FROTHLY\richschlitzer — Richard's workstation (LockBit ransomware)


MITRE ATT&CK

T1078 – Valid Accounts — Nathaniel using Richard's credentials
T1486 – Data Encrypted for Impact — LockBit on Richard's host


Wonderland SOC | Splunk Blue Team Academy | Cisco NetAcad Cybersecurity Defense Analyst – Course 5
