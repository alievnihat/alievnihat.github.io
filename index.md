# Microsoft 365 Threat Investigation & Response Lab

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
