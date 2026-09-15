```markdown
# Active Directory Threat Detection Platform

**Enterprise threat detection for advanced Active Directory attacks - Kerberoasting, DCSync, lateral movement**

## Project Highlights

- Active Directory threat detection
- Kerberos attack analytics
- DCSync detection
- Lateral movement detection
- Privileged access monitoring
- MITRE ATT&CK mapping
- PostgreSQL-backed event storage
- Security dashboard development

## Project Outcome

This project demonstrates how Active Directory telemetry, Kerberos analytics, detection engineering, and event correlation can be used to identify advanced identity-based attacks and generate investigation-ready alerts for security operations teams.


## Security Skills Demonstrated

- Active Directory Security Monitoring
- Detection Engineering
- Kerberos Analysis
- Threat Hunting
- Lateral Movement Detection
- Privileged Access Monitoring
- MITRE ATT&CK Mapping
- Incident Investigation
- PostgreSQL Database Design
- Security Automation


## 🎯 What This System Detects

✅ **Kerberoasting** (T1558.003) - Service account credential theft (157 TGS in 5 min)  
✅ **DCSync** (T1003.006) - Domain controller replication abuse  
✅ **Lateral Movement** (T1021) - SMB, RDP, WinRM unauthorized access  
✅ **Golden Tickets** (T1558) - Forged Kerberos tickets  
✅ **Privilege Escalation** - Unauthorized Domain Admin access  
✅ **Brute Force** (T1110) - Password spray attacks  
✅ **AD Reconnaissance** (T1087.002) - LDAP enumeration detection  
✅ **LSASS Dumping** (T1003.001) - Credential memory access  


## 🏗️ System Architecture

```
Kerberos Events (4768, 4769, 4770, 4771)
Security Events (4624, 4625, 4648)
Sysmon Events :
  - Event ID 1 (Process Creation)
  - Event ID 3 (Network Connection)
  - Event ID 11 (File Creation)
  - Event ID 13 (Registry Modification)
  - Event ID 22 (DNS Query))
RDP/Terminal Services Events
        ↓
Event Collection & Parsing
        ↓
PostgreSQL Database
        ↓
8 Specialized Detection Engines
  ├─ Kerberos Parser (46K+ events analyzed)
  ├─ Lateral Movement Detector (SMB, RDP, WinRM)
  ├─ DCSync Detector (replication abuse)
  ├─ Privileged Access Monitor (Domain Admin)
  ├─ Password Spray Detector (brute force)
  ├─ Persistence/Backdoor Detector (golden tickets)
  ├─ Admin Tool Abuse Detector (BloodHound, PowerView)
  └─ UEBA Behavioral Analytics
  
  - Windows Server 2022 Domain Controller
  - Windows 10 Client
  - Sysmon Telemetry Collection
  - Active Directory Domain (corp.local)
  - PostgreSQL Backend
  - Kali Linux Analysis Host
        ↓
Real-time Alerting & Threat Hunting
```

## Detection Logic Examples
```python
# KERBEROASTING DETECTION
KERBEROASTING_TICKET_THRESHOLD = 3      # 3+ TGS per SPN in time window
KERBEROASTING_WINDOW_MINUTES = 10       # Within 10 minutes
CONFIDENCE_KERBEROASTING = 90            # 90% confidence

# BRUTE FORCE DETECTION
BRUTE_FORCE_FAILURE_THRESHOLD = 5       # 5+ failed logins
PASSWORD_SPRAY_USER_THRESHOLD = 5       # 5+ different users targeted
TIME_WINDOW_MINUTES = 10

# LATERAL MOVEMENT PORTS
LATERAL_MOVEMENT_PORTS = [135, 139, 445, 3389, 5985, 5986]
# RPC(135), NetBIOS(139), SMB(445), RDP(3389), WinRM(5985/5986)

# DCSYNC DETECTION
DCSYNC_REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # Replication Services
    "19195a5b-6da0-11d0-afd3-00c04fd930c9",  # Directory Replication
}
```

## 📋 Sample Detections

### Detection #1: Kerberoasting

```
[CRITICAL] Kerberoasting Attack Detected

Time: 2024-01-15 14:23:45
User: example_user
Target SPN: sqlserver_svc
Requests: 157 TGS in 5 minutes
Confidence: 90%
MITRE: T1558.003

Normal: 10-20 TGS/hour per SPN
Detected: 157 in 5 minutes = 840% ABOVE BASELINE

ACTION:
1. BLOCK source IP (192.168.1.50)
2. RESET sqlserver_svc password
3. CHECK for lateral movement
4. PRESERVE logs

(Attacker would have cracked password offline)
```

### Detection #2: DCSync Attack

```
[CRITICAL] DCSync Attack Detected (Domain Takeover)

Time: 2024-01-15 15:30:00
User: attacker_account
Event: Directory Replication Request
GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
Confidence: 95%
MITRE: T1003.006

What's Happening:
- Non-DC account requesting DC replication
- Attempting to copy ENTIRE AD database
- Including all passwords and secrets

ACTION:
1. ISOLATE account immediately
2. FORCE password reset ALL accounts
3. RESTORE domain from clean backup
4. CALL incident response team

(Complete domain compromise prevented)
```

### Detection #3: Lateral Movement

```
[HIGH] Suspicious Lateral Movement

Time: 2024-01-15 15:45:20
Source: WORKSTATION-01
Target: SERVER-01
Method: SMB Port 445
User: service_account
Confidence: 65%

Analysis:
- john.smith never accessed this server before
- Connection at 3:00 AM (unusual)
- Using service account (atypical)

ACTION:
1. Investigate source host
2. Check target for suspicious activity
3. Reset service account password
4. Review data access
```

## 🔧 Technology Stack

- **Python 3.8+** - Detection engines
- **PostgreSQL** - Event storage (tested 100K+/day)
- **Kerberos Events** - 4768, 4769, 4770, 4771, 4776
- **Sysmon** - Process/network/registry telemetry
- **Flask** - Web dashboard
- **Machine Learning** - Isolation Forest for UEBA

## 📦 Requirements

```
pandas
sqlalchemy
psycopg2-binary
flask
pyyaml
python-dateutil
python-evtx
```

## 🚀 Quick Start

```bash
git clone https://github.com/geniusdeeg-security/ad-threat-detection-platform
cd ad-threat-detection-platform
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./run_complete_pipeline.sh
python app.py  # Dashboard at http://localhost:5000
```

## Project Structure

```text
ad_detection_platform/
│
├── collectors/
│   └── Event collection modules
│
├── detections/
│   └── AD attack detection engines
│
├── database/
│   └── PostgreSQL integration
│
├── dashboard/
│   └── Flask web dashboard
│
├── mitre/
│   └── ATT&CK mappings
│
├── exports/
│   └── SIEM exports and reports
│
├── logs/
│   └── Parsed event logs
│
├── reports/
│   └── Detection reports
│
├── win_server/
│   └── Windows Server event sources
│
├── win_10/
│   └── Windows 10 event sources
│
├── new_rdp_logs/
│   └── RDP investigation datasets
│
├── app.py
├── run_complete_pipeline.sh
└── README.md
```

## Database Schema

```text
security_events
sysmon_events
alerts
detection_results
ad_users
ad_computers
rdp_sessions
mitre_techniques
```

## Repository Scope

This repository contains the core detection framework used for learning, research, and portfolio demonstration purposes.

Sensitive deployment-specific configurations, integrations, tuning parameters, and operational workflows are intentionally excluded.

### Public Components

✅ Kerberos analytics framework
✅ Active Directory detection logic
✅ MITRE ATT&CK mapping
✅ Threat hunting workflows
✅ Detection framework

### Private Components

❌ Environment-specific tuning
❌ Production deployment configurations
❌ SIEM integrations
❌ Alert-routing workflows
❌ Incident response playbooks
❌ Organization-specific detection content
❌ Proprietary threat-hunting queries


## Screenshots

### Dashboard

<img width="947" height="915" alt="Screenshot From 2026-09-10 19-48-49" src="https://github.com/user-attachments/assets/b31af0b9-6402-4bba-94b8-b0c1df9d4b26" />

<img width="947" height="470" alt="Screenshot From 2026-09-10 19-49-05" src="https://github.com/user-attachments/assets/17efdc33-ebd4-4aad-816c-ba2a3c6f5215" />

<img width="948" height="678" alt="Screenshot From 2026-09-10 19-49-45" src="https://github.com/user-attachments/assets/8ab460f2-ddda-4323-8af1-2a24d3952268" />

### Database Analysis

<img width="903" height="945" alt="Screenshot From 2026-09-10 09-24-50" src="https://github.com/user-attachments/assets/e5ba153b-4253-4e2d-a18a-b0e4093c1829" />


<img width="912" height="942" alt="Screenshot From 2026-09-10 18-21-36" src="https://github.com/user-attachments/assets/779c4759-ce86-48dd-a8a3-84a8bd81658b" />


<img width="912" height="942" alt="Screenshot From 2026-09-10 18-21-46" src="https://github.com/user-attachments/assets/8d03d3d8-cc57-4e6b-aa31-543792e763c5" />

<img width="912" height="942" alt="Screenshot From 2026-09-10 18-21-58" src="https://github.com/user-attachments/assets/c816a88f-a52d-4882-8caa-d49360041275" />

<img width="912" height="942" alt="Screenshot From 2026-09-10 18-22-10" src="https://github.com/user-attachments/assets/70c9382d-b8d7-48e2-a85c-6d0011c70b97" />


### Detection Results

<img width="940" height="955" alt="Screenshot From 2026-09-15 21-06-05" src="https://github.com/user-attachments/assets/eb3b13a5-9576-4a03-a7a9-657c26aad97f" />


<img width="940" height="955" alt="Screenshot From 2026-09-15 21-06-16" src="https://github.com/user-attachments/assets/0bd8da24-7361-4f0e-bc73-2743a896f700" />


<img width="940" height="955" alt="Screenshot From 2026-09-15 21-06-34" src="https://github.com/user-attachments/assets/871953f7-4f0f-4e0b-a51e-c45249c10a0d" />


<img width="940" height="955" alt="Screenshot From 2026-09-15 21-06-42" src="https://github.com/user-attachments/assets/a3a0fbbf-774c-4d89-8595-085ffffcd2ba" />


<img width="940" height="955" alt="Screenshot From 2026-09-15 21-07-02" src="https://github.com/user-attachments/assets/3ae89370-3102-4569-a835-d54bdfc534bf" />


<img width="947" height="955" alt="Screenshot From 2026-09-15 21-07-24" src="https://github.com/user-attachments/assets/459a58ee-1774-4b56-a00d-feae8778a65a" />


<img width="947" height="955" alt="Screenshot From 2026-09-15 21-07-33" src="https://github.com/user-attachments/assets/253be428-48bf-4b08-be46-0a74211d48ed" />


<img width="947" height="955" alt="Screenshot From 2026-09-15 21-07-44" src="https://github.com/user-attachments/assets/2e32f48b-4606-4d02-b8e1-4c4128751bea" />


<img width="945" height="766" alt="Screenshot From 2026-09-15 21-08-05" src="https://github.com/user-attachments/assets/8decb63b-e1f0-48ad-bd3c-7fd2c8ad7754" />

<img width="948" height="949" alt="Screenshot From 2026-09-15 21-08-32" src="https://github.com/user-attachments/assets/4601c8a7-2074-401d-94c3-b93cbf25909c" />


<img width="946" height="957" alt="Screenshot From 2026-09-15 21-09-02" src="https://github.com/user-attachments/assets/d553b089-74e1-4676-9d08-679ff4dac34c" />


<img width="940" height="313" alt="Screenshot From 2026-09-10 19-47-26" src="https://github.com/user-attachments/assets/061a3f78-0c8c-4081-be1f-67bd8fb13cc2" />


## Connect With Me

* **LinkedIn:** [Charles Arinze](https://www.linkedin.com/in/charlesarinze)
* **GitHub:** [geniusdeeg-security](https://github.com/geniusdeeg-security)
* **Jobberman:** Available on my Jobberman professional profile


## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Credential Access | Kerberoasting (T1558.003) | ✅ |
| Credential Access | DCSync (T1003.006) | ✅ |
| Lateral Movement | Remote Services (T1021) | ✅ |
| Persistence | Golden Tickets (T1558) | ✅ |
| Privilege Escalation | Domain Admin Changes | ✅ |
| Discovery | LDAP Enumeration (T1087.002) | ✅ |


## Status

✅ Fully Functional Lab Implementation
✅ Tested End-to-End
✅ Portfolio Project

---


## Career Interests

Open To:
- Remote Roles
- Hybrid Roles
- On-Site Roles
- Paid Internship Opportunities

Target Roles:
- Detection Engineer
- Security Analyst
- SOC Analyst
- SOC Analyst II
- Threat Hunter
- Blue Team Analyst


## License

This project is licensed under the MIT License.


**Built by:** ARINZE CHARLES
