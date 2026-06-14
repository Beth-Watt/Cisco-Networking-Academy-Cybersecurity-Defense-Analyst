# Incident 3 - Creation of Shadow Copy

Wonderland SOC | Cisco NetAcad Cybersecurity Defense Analyst | Course 5  
Analyst: Elizabeth Watt | Platform: Splunk Blue Team Academy

---

## Overview

A high-urgency notable event fired for shadow copy creation on Frothly's Active Directory Server, Labrador. A shadow copy duplicates everything on a volume at a point in time. That's not automatically malicious, but this one was deleted almost immediately after it was created. That made it worth investigating.

It ended up connecting to a malicious JavaScript file, abuse of the Print Spooler service, credential access, lateral movement via Remote PowerShell, and outbound traffic to an external IP.

---

## Finding - Creation of Shadow Copy

### What triggered the alert

`vssadmin.exe` executed on Labrador (192.168.70.150). The shadow copy was gone within minutes of being created. That pattern is consistent with an attacker snapshotting the volume to dump credentials, then cleaning up.

Running the search confirmed `vssadmin.exe` had executed twice within three minutes.

### What else was happening on Labrador

- Large volume of outbound web traffic
- Remote PowerShell launches
- Registry Autoruns being added
- Excessive failed logins for `pcerf@froth.ly` - priority: high
- Outbound traffic to `152.195.19.97`

### Tracing it back

The Print Spooler service (`spoolsv.exe`) was using `wscript.exe` to run a Node.js file called `hefeweizen_tips.js`. That file created and deleted the shadow copy, moved files on the domain controller, mounted a network drive, and copied files out to it.

The file was downloaded to `mvalitus I.froth.ly` at 18:31 on 8/18/2020. The source IP was `46.101.247.84`, tied to `https://dunkelhefeweizen.azureedge.net/index.html` - a suspicious Azure CDN address serving the script.

### Confirming it was unauthorized

I consulted a SME who suggested it was likely a true positive and recommended confirming with Frothly's IT before escalating. I reached out to Grace, Frothly's IT lead. She confirmed no shadow copy activity had been ordered and that Peat Cerf (`pcerf`) had not initiated anything.

Confirmed true positive. Peat Cerf wasn't doing anything wrong, his account was being used without his knowledge.

---

## How It Connected

The alert started with the shadow copy. A malicious script was delivered to a host on the network, executed through the Print Spooler under a legitimate user's context, used to stage or dump data, then cleaned up. Remote PowerShell on the same server pointed to lateral movement. The outbound traffic pointed to external C2.

`pcerf` shows up as the account context throughout, but he didn't do this.

---

## Indicators of Interest

- `pcerf` / `pcerf@froth.ly` - Peat Cerf (victim, account used without authorization)
- `mvalitus` - other alias involved
- `hefeweizen_tips.js` - malicious Node.js file
- `46.101.247.84` - source IP for the script
- `https://dunkelhefeweizen.azureedge.net/index.html` - delivery domain
- `152.195.19.97` - external IP receiving outbound traffic from Labrador
- Labrador - 192.168.70.150 (Frothly Active Directory Server)

---

## MITRE ATT&CK

- T1003.003: OS Credential Dumping: NTDS
- T1021.006: Remote Services: Remote Windows Management
- T1090.004: Proxy: Domain Fronting

---

## SPL Searches

### 3.1 - Windows Event Logs: vssadmin.exe on Labrador
```spl
index=main sourcetype=xmlwineventlog EventCode=1 dest=labrador process_name=vssadmin.exe
| table _time user process process_exec parent_process
| sort _time +
```

### 3.2 - Peat Cerf credentials on Labrador via Print Spooler
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where
Processes.parent_process_name="spoolsv.exe" Processes.dest="labrador.froth.ly" Processes.user="pcerf"
groupby _time span=1s Processes.parent_process Processes.process
```

### 3.3 - All wscript.exe activity across the environment
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where
Processes.process_name="wscript.exe" groupby _time span=1s Processes.process
Processes.process_name Processes.parent_process Processes.dest Processes.user
```

### 3.4 - Endpoint filesystem: hefeweizen_tips.js
```spl
| tstats summariesonly=true count values(Filesystem.file_size) AS file_size from
datamodel=Endpoint.Filesystem where Filesystem.file_name="*hefeweizen_tips.js*" groupby _time span=1s
Filesystem.file_name Filesystem.file_path
`drop_dm_object_name("Filesystem")`
| table _time file_name file_path
| sort + _time
```

### 3.5 - Web data model: hefeweizen_tips.js download activity
```spl
| from datamodel:"Web"."Web"
| search (url="*hefeweizen_tips.js*")
| head 100
```

### 3.6 - DNS: Labrador resolving to external IP
```spl
transaction sourcetype=stream:dns dest_ip="192.168.70.150" answer="152.195.19.97" record_type=A
| table timestamp hostname{}
```

### 3.6b - Labrador traffic to suspicious IP
```spl
index=main host=labrador dest_ip=46.101.247.84 AND *hefeweizen*
| sort _time
```

---

Wonderland SOC | Splunk Blue Team Academy | Cisco NetAcad Cybersecurity Defense Analyst | Course 5
