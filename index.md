# Nihat Aliev · Cybersecurity & Blue Team Labs

> SIEM, XDR, Incident Response, and Detection Engineering projects.

## Index
- [Microsoft 365 Threat Investigation & Response Lab](#microsoft-365-threat-investigation--response-lab)
- [Microsoft Sentinel SIEM & SOAR Automation Lab](#microsoft-sentinel-siem--soar-automation-lab)
- [Windows & Azure Vulnerability Management Lab](#windows--azure-vulnerability-management-lab)
- [SOC Level 1 Analyst Learning (TryHackMe)](#soc-level-1-analyst-learning-tryhackme)

---

## Microsoft 365 Threat Investigation & Response Lab

## Overview
This project is a hands-on Microsoft 365 E5 lab built to explore how **Defender for Office 365**, **Microsoft Defender XDR**, **Entra ID**, and **Sentinel** work together to detect and respond to phishing and credential-theft threats.

The lab simulates realistic attack scenarios using Safe Links, phishing simulations, and custom phishing emails, then tracks the detection flow from Microsoft 365 Defender into Sentinel.  
All work was performed in an isolated Microsoft 365 E5 developer tenant.

---

## Environment Setup

### Tenant & Test Accounts
The lab uses a single Microsoft 365 E5 developer tenant:  
**Domain:** `nihatlab.onmicrosoft.com`

Five test accounts were created to represent users and analysts:
- Alice User  
- Bob User  
- Chris User  
- Analyst User  
- Nihat Aliev  

Each account was licensed with **Office 365 E5 (no Teams)**.  
Administrative roles were added in Entra ID for:
- **Privileged Role Administrator**
- **Security Reader**

![User List](screenshots/2.%20User%20List.png)
![Entra ID Roles](screenshots/8.%20Create%20EntraID%20roles.png)

---

### Safe Links Policy
A Safe Links policy was configured to protect both inbound and internal messages.

**Policy:** `SafeLinks Lab`  
**Included Users:** Alice, Bob, Chris  
**Settings:**
- URL rewriting and scanning – **Enabled**  
- Real-time URL scanning – **Enabled**  
- Scan before delivery – **Enabled**  
- API checks – **Enabled**

This ensures any URL in email is analyzed before a user can access it.

![Safe Links Policy](screenshots/3.%20SafeLinks%20Policy.png)

---

### Log Analytics & Sentinel Setup
A **Log Analytics Workspace** (`Sentinel-Workspace`) was deployed in Azure (UK South).  
Microsoft Sentinel was then enabled and linked to this workspace.

After deployment, **Defender XDR** was connected to Sentinel to stream logs from:
- EmailEvents  
- MessageEvents  
- UrlClickEvents  
- SigninLogs  
- AlertInfo  
- AlertEvidence  

![Log Analytics Workspace](screenshots/9.%20Create%20Log%20Analytics.png)
![Sentinel Connection](screenshots/10.%20Connect%20Defender%20to%20Sentinel.png)

---

## Attack Simulations

### Built-in Phishing Simulation
Using **Attack Simulation Training** in Defender for Office 365, a baseline credential-harvesting campaign was launched.

**Scenario:** Credential Harvest  
**Delivery Platform:** Email  
**Results:**
- 1 user clicked the link  
- 0 users submitted credentials  

The simulation verified message delivery and interaction telemetry within Defender.

![Phishing Simulation](screenshots/11.%20Baseline%20Phishing%20Simulation.png)

---

### Custom Phishing Email
A manual phishing message was crafted and sent to Chris User to simulate a real-world credential-theft attempt.

**Subject:** “Important Notification – Your TESCO account will be suspended”  
**Sender:** `pat@docstoreinternal.com` (spoofed)  
**Payload:** Fake "Get Started" link to a dummy page.  

The message was delivered and opened successfully.

![Phishing Email](screenshots/13.%20Phishing%20Email.png)

---

## Detection & Analysis

### Threat Explorer
Defender’s **Threat Explorer** dashboard was used to monitor message delivery and user interactions.  
It displayed messages from:
- `attacksimulationtraining.com`
- `microsoft.com`
- `nihatlab.onmicrosoft.com`

Delivery actions and timestamps confirmed detection worked as expected.

![Threat Explorer](screenshots/6.%20Threat%20Explorer%20working.png)
![Email Explorer](screenshots/14.%20Email%20Explorer.png)

---

### Advanced Hunting (KQL)
Email telemetry was verified using **Advanced Hunting** in Defender XDR.

```kql
EmailEvents
| sort by Timestamp desc
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, ThreatTypes
| take 20
This confirmed the lab’s phishing events appeared correctly in the `EmailEvents` table and were being synchronised to Sentinel.
```
---

## Sentinel Integration
After connecting Sentinel to Defender XDR, multiple data tables became available for correlation:

- `EmailEvents`  
- `SigninLogs`  
- `AlertInfo`  
- `MessageEvents`  
- `UrlClickEvents`  

This allows incidents to be traced from delivery to user sign-in and alert generation, all within Sentinel.

**Workspace:** `Sentinel-Workspace (UK South)`  
**Connection Status:** ✅ Connected  

---

## Key Results

| Metric | Value |
|---------|--------|
| Simulated phishing emails | 19 |
| Users who clicked | 1 |
| Credentials submitted | 0 |
| Alerts generated | 10+ |
| Duplicate alerts reduced | ~25% |
| Defender → Sentinel data tables | 6 |

---

## Example Hunting Queries

### Email → Sign-in Correlation
<pre lang="kql"><code>
let phish = EmailEvents
| where ThreatTypes has "Phish"
| project PhishTime=Timestamp, Recipient=RecipientEmailAddress;
SigninLogs
| join kind=inner (phish) on $left.UserPrincipalName == $right.Recipient
| where TimeGenerated between (PhishTime .. PhishTime + 1h)
| project UserPrincipalName, IPAddress, Location, PhishTime
</code></pre>

### URL Click Tracking
<pre lang="kql"><code>
UrlClickEvents
| where Timestamp > ago(7d)
| project Timestamp, UserPrincipalName, Url, ClickAction, DetectionMethods
| sort by Timestamp desc
</code></pre>


---

## MITRE ATT&CK Mapping

This lab aligns with several key techniques in the [MITRE ATT&CK framework](https://attack.mitre.org/):

| Tactic | Technique | Description |
|--------|------------|-------------|
| **Initial Access** | [T1566.001 – Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) | Simulated phishing emails with malicious attachments and Safe Attachments inspection. |
| **Initial Access** | [T1566.002 – Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | Simulated credential-harvesting campaigns using Safe Links. |
| **Credential Access** | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Detection of compromised or reused credentials from phishing tests. |
| **Defence Evasion** | [T1070 – Indicator Removal](https://attack.mitre.org/techniques/T1070/) | Testing log integrity and visibility after simulated user actions. |
| **Discovery** | [T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/) | Monitoring Entra ID sign-ins for reconnaissance or enumeration attempts. |

---

## Takeaways
- Defender for Office 365 provided detailed telemetry for message delivery and clicks.  
- Safe Links effectively stopped users from visiting known malicious domains.  
- Connecting Defender XDR to Sentinel created a unified investigation view.  
- Tuning alert rules reduced redundant notifications by about 25%.  
- KQL hunting is invaluable for validating telemetry and building correlations.  

---

## Summary
This lab demonstrates an end-to-end Microsoft 365 threat investigation workflow - from email delivery and Safe Links inspection, through phishing simulations, to data correlation in Sentinel.  
It provides a clear view of how Microsoft’s security stack works together for detection, hunting, and response.
