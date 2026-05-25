# Course 8: Introduction to Threat Hunting

I come from 16+ years of Orientation and Mobility — teaching people who are blind or visually impaired to navigate the physical world safely. Threat hunting clicked for me immediately because it's the same concept, just in a digital environment. You're not waiting for something bad to happen. You're proactively looking for danger before it finds someone vulnerable.

## So what is threat hunting exactly?

It's a human-driven process of finding security incidents that automated systems missed. The key word is *human* — because computers struggle with unpredictable human behavior. That's where we come in. It's a proactive strategy, sometimes called "shifting left," meaning you're getting ahead of threats rather than reacting to them.

## The 3 frameworks I learned

- **SQRRL (2015)** — the original
- **TaHiTI (2018)** — intelligence-led
- **PEAK (2022)** — Prepare, Execute, Act, Knowledge — this is what this course focuses on

## 3 ways to hunt

- **Hypothesis-driven** — you have a hunch or intel that leads you to look for specific behavior
- **Baseline hunting** — you learn what "normal" looks like and go looking for outliers
- **Model-assisted (M-ATH)** — machine learning helps surface suspicious patterns

## The ABLE Method

This is used in the Prepare phase to sharpen your hunt goals before you ever touch the data:

- **A** — Actor (who or what type of threat)
- **B** — Behavior (TTPs, how data is being moved or exfiltrated)
- **L** — Location (where in the environment to look)
- **E** — Evidence (what would confirm or deny the behavior exists)

## Baselining — finding "normal"

This was one of the more interesting parts of the course for me. Before you can spot an outlier, you have to know what normal looks like — and normal is different in every environment. You review distributions, look at averages and medians, and identify the most common categories and unique values in your key fields.

One statistical tool I learned here is **IQR (Interquartile Range)** — it measures the spread of the middle 50% of your data. Anything sitting way outside that range is worth a closer look. Think of it like knowing the typical travel patterns of a student — when something is way off route, you notice it immediately.

## The Data Dictionary

Before you hunt, you build a data dictionary — a reference that defines your important fields, their data types, their values, and what those values mean. It keeps everyone on the team speaking the same language, which matters a lot when you're working across a SOC.

## SPL commands I used

- `sourcetype=xmlwineventlog` for Windows event logs
- Sysmon events and the Endpoint Datamodel (CIM)
- `rare`, `sort`, `stats`, `eventstats`, `streamstats` for surfacing outliers

## Regex — not as scary as it looks

I'm not going to lie, regex looked like gibberish at first. In this course we watched a Splunk analyst walk through how they work rather than building them ourselves — but using [regex101.com](https://regex101.com/) to test expressions on my own made it click. I actually thought it was kind of fun once I stopped being intimidated by it. Something I want to dig into more hands-on down the road.

Splunk uses two commands: `rex` to extract strings and `regex` to filter results.

## Practical lab — Splunk T-Shirt Co.

We used a simulated dataset to hunt for potential data exfiltration and command-and-control activity using `sourcetype=stream:http`. The goal was to find unusually high `bytes_out` values — a red flag for data leaving the network that shouldn't be. We also referenced MITRE ATT&CK techniques T1059 and T1562.001 and used [research.splunk.com](https://research.splunk.com/) to dig into Windows Defense Evasion tactics.

## What I took away from this course

Threat hunting is methodical, not random. You form a hypothesis, define what normal looks like, gather and filter your data, and then look for what doesn't fit. That process feels very familiar to me — it's exactly how I approach assessing a new environment for a student. You learn the landscape first, then you notice what's out of place.

**Next up:** finishing the Splunk path, then Wireshark, then TryHackMe SOC1.
