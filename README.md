# Home Lab #4 – Credential Access Detection Playbook (Splunk + MITRE ATT&CK)

## Project Overview
This project expands on my earlier Splunk and Python labs by building a **defensive playbook aligned with MITRE ATT&CK**.  The focus is on **correlating failed SSH authentication attempts**, applying **risk scoring**, and documenting the process as a repeatable SOC workflow.  

- **Project #1:** Installed Splunk & ingested Linux logs (foundation).  
- **Project #2:** Built Splunk detection for failed logins (single-source detection).  
- **Project #3:** Parsed logs with Python to create attacker IP lists (automation).  
- **Project #4 (this project):** Correlated detections, scored attacker risk, and aligned the workflow to a **MITRE ATT&CK playbook** for SOC escalation.  

---

## Goals
- Detect repeated failed SSH login attempts using Splunk SPL.  
- Correlate attacker IPs and assign **risk scores** to prioritize threats.  
- Align detection logic with **MITRE ATT&CK T1110 (Brute Force)** under the Credential Access tactic.  
- Demonstrate how detections become **SOC playbooks** that guide incident response.  

---

## Tools & Data
- **Splunk Enterprise Cloud (Free Trial)** – SIEM platform.  
- **Sample Linux Auth Log (`auth.log`)** – contains failed SSH login events.  
- **SPL Queries** – for extraction, correlation, and risk scoring.  

*(Earlier labs also used Python parsers to generate IP lists. This project focuses on **Splunk-only correlation** to emphasize SOC workflows.)*  

---

## Detection & Correlation Workflow

## 1. Extract IPs from failed login events
```
index=* authentication failure
| rex field=_raw "rhost=(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
```
Screenshot: <img width="1244" height="597" alt="Splunk Query Output - Auth Failure" src="https://github.com/user-attachments/assets/edae8463-246e-4324-87dd-57b3365428a4" />

## 2. Count failed logins per IP
```
index=* authentication failure
| rex field=_raw "rhost=(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as fail_count by src_ip
| sort - fail_count
```
Screenshot: <img width="1271" height="841" alt="Splunk Query Output - Fail Per IP" src="https://github.com/user-attachments/assets/13912e91-5fa9-4be1-9a0b-2616216ade59" />

## 3. Assign risk scores
```
index=* authentication failure
| rex field=_raw "rhost=(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as fail_count by src_ip
| eval risk = case(
    fail_count>=50, 90,
    fail_count>=20, 70,
    fail_count>=10, 50,
    true(), 10
)
| table src_ip fail_count risk
| sort - risk - fail_count
```
Screenshot: <img width="1705" height="964" alt="Splunk Query Output - Risk Scoring" src="https://github.com/user-attachments/assets/711320b0-bf93-4192-8e84-48bd246ab1fa" />

## 4. Dashboard Panels

- Table: Top attacker IPs with fail counts and risk scores.
- Bar Chart: Failed login trends over time.

Screenshot: <img width="1404" height="840" alt="Splunk Dashboard Panel" src="https://github.com/user-attachments/assets/536fdc8c-4085-458f-9fb5-c569c468e0c4" />

## 5. Alert Configuration (Log Event & Send Email)

- Triggers when fail count > 20 within 10 minutes. This alert is labeled as MITRE ATT&CK T1110 - Credential Access.

Screenshot: <img width="795" height="852" alt="Splunk Alert Config" src="https://github.com/user-attachments/assets/f2053e2d-9499-4cd6-af56-aeb50fe08544" />

## MITRE ATT&CK as a Playbook

- This lab wasn’t just about finding failed logins. It was about turning detection into a repeatable SOC playbook:
- Tactic: Credential Access
- Technique: T1110 – Brute Force

Playbook Steps

- Detect: Spot repeated failed SSH logins in Splunk (SPL query).
- Correlate: Aggregate attacker IPs across events to identify persistence.
- Prioritize: Apply a risk score to highlight high-volume attackers.
- Escalate: Trigger alerts for Tier 1/2 SOC review.
- Respond: Verify malicious activity, check threat intel, and recommend containment (e.g., block IP, SOAR workflow).

💡 Why It Matters

MITRE ATT&CK transforms this project from a single Splunk query into a structured defensive playbook. This mirrors how real teams standardize incident response and escalation.

## Key Takeaways

- I learned how to correlate multiple log sources into a unified detection.
- I applied risk scoring to prioritize attacker IPs.
- I aligned workflow with MITRE ATT&CK to show playbook-driven detection.
- I demonstrated progression: setup (Proj #1) → detection (Proj #2) → automation (Proj #3) → playbook correlation (Proj #4).
