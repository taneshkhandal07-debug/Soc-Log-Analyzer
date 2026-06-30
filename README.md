# 🛡 SOC Threat Detection & Log Analyzer

🚀 **Live Demo:**
👉 https://soc-log-analyzer.streamlit.app/
SOC Threat Detection & Log Analyzer
Security analysts spend a disproportionate share of their day manually scanning log files for threats — a slow, repetitive process that contributes to alert fatigue and delays real incident response. This project automates the first-pass triage (parsing, anomaly detection, risk scoring, and report drafting) so analysts can spend their time on judgment calls and investigation instead of manual log review.

It's an augmentation tool, not a replacement for analyst judgment — the system surfaces and prioritizes what's worth a human's attention; it doesn't make the final call.

Who this is for

Built primarily for security analysts dealing with alert fatigue and high log volumes who need help prioritizing what actually matters, and secondarily for cybersecurity students who want hands-on exposure to SOC detection workflows without needing access to a real production environment or real attack data.

How it works

Detection — Logs are parsed into structured security events, then checked against five detection types: brute force attempts, suspicious logins, multi-IP coordinated attacks, time-based anomalies (activity outside normal hours), and geo-IP anomalies (logins from unexpected locations).

Risk classification — Every detected event is automatically scored Low / Medium / High, so analysts can triage by severity instead of reading every alert in order.

Threat intelligence enrichment — Suspicious IPs are checked against reputation data to flag known-malicious sources, adding context an analyst would otherwise have to look up manually.

Dashboard — A live view across four panels: threat overview, active alerts, raw event logs, and generated reports — built so the analyst doesn't have to leave one screen to investigate.

Attack simulator — Generates synthetic logs for all five attack types, so detection logic can be validated without needing real attack data (useful both for testing and for the student/training use case).

Incident reporting — One-click export to TXT or PDF, turning raw detection output into something that can actually be shared with a team or documented for follow-up.

Product decisions

A few calls made deliberately when scoping v1, rather than just "what I had time to build":


Rule-based detection over ML, for now. Thresholds and pattern rules are transparent and easy to tune — important for a security tool, where an analyst needs to trust why something was flagged. ML-based detection is scoped for a later phase once there's enough labeled data to validate it properly.
No real-time streaming in v1. Log upload is batch-based rather than live-streamed. This was a conscious scope cut to ship a working detection pipeline first, with real-time monitoring planned as a phase 2 addition rather than blocking v1 on it.
No multi-user auth/RBAC yet. Acceptable for a single-analyst workflow and for the portfolio/training use case, but flagged as a gap before this could be used by an actual team — role-based access is on the roadmap.
False positives vs. false negatives were treated as different risk levels, not just "errors to minimize evenly." Missed detections (false negatives) were treated as higher-impact than over-flagging (false positives), since under-detecting a real threat is more costly than an analyst dismissing a false alarm — this shaped how detection thresholds were tuned.
File upload validation was treated as a security requirement, not an edge case — uploaded files are sanitized and validated, since a tool meant to analyze attacks shouldn't itself be an attack vector.


What's deliberately out of scope for v1: real-time log streaming, SIEM integration, ML-based detection, role-based access control, external threat intel APIs — all roadmapped for later phases rather than cut entirely.

How success was defined

Rather than just "does it run," the project was scoped against:


Detection accuracy and alert generation time
Report generation time
Volume of logs successfully analyzed
High-risk events correctly identified


Tech stack

Python backend, Streamlit frontend/dashboard, Pandas/NumPy for log processing, Plotly for visualization, PDF generation for reporting.

Setup

# clone the repo
git clone https://github.com/taneshkhandal07-debug/Soc-Log-Analyzer.git
cd Soc-Log-Analyzer

# install dependencies
pip install -r requirements.txt

# run the app
streamlit run app.py
---

## ⚡ Key Features

### 🔍 Threat Detection Engine

* Brute Force Attack Detection
* Suspicious Login Pattern Detection
* Multi-IP Attack Detection
* Time-based Anomaly Detection
* Geo-IP Anomaly Detection

---

### 🧠 Risk & Threat Intelligence

* Automated risk classification:

  * 🟢 Low
  * 🟡 Medium
  * 🔴 High
* Malicious IP enrichment (Threat Intelligence)

---

### 🧪 Smart Attack Simulator

* Generate synthetic logs for:

  * Brute Force
  * Multi-IP Attacks
  * Time Anomalies
  * Geo Anomalies
  * Combined attack scenarios
* Useful for testing detection pipelines

---

### 📊 Advanced Analytics Dashboard

* Cyber-themed interactive UI
* Tabs:

  * 📊 Overview
  * 🚨 Alerts
  * 📄 Logs
  * 🧾 Reports

---

### 📈 Visualization & Insights

* 🔥 Top Attacking IPs Chart
* 📊 Attack Timeline
* 🔥 Attack Frequency Heatmap
* 👤 User Activity Tracking

---

### 📤 Export & Reporting

* 📄 Download incident report (TXT)
* 📥 Download report as PDF
* 📤 Export filtered logs (JSON)

---

## 🏗 Project Structure

```bash
soc-log-analyzer/
│
├── modules/
│   ├── parser.py
│   ├── detector.py
│   ├── risk_engine.py
│   ├── reporter.py
│   ├── threat_intel.py
│   ├── time_anomaly.py
│   ├── multi_ip_attack.py
│   ├── geo_ip.py
│   ├── attack_simulator.py
│   ├── pdf_report.py
│
├── data/
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository

```bash
git clone https://github.com/<your-username>/Soc-Log-Analyzer.git
cd Soc-Log-Analyzer
```

---

### 2️⃣ Create virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

---

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Run the application

```bash
streamlit run app.py
```

---

## 🧪 How to Use

1. Upload a `.log` file
2. Select detection settings
3. (Optional) Generate attack logs using simulator
4. Analyze:

   * Alerts
   * Risk levels
   * Timeline
   * Reports

---

## 🎯 Key Concepts Demonstrated

* Security Log Analysis
* Anomaly Detection
* SOC Workflow Simulation
* Threat Intelligence Integration
* Data Visualization & Analytics
* Attack Simulation & Validation

---

## 🚀 Future Enhancements

* Real-time log streaming
* Machine learning-based anomaly detection
* Integration with external threat intelligence APIs
* Role-based authentication system
* Cloud deployment scaling

---

## 👨‍💻 Author

**Tanesh Khandal**
🎓 JECRC University
💻 Cybersecurity & Tech Enthusiast

---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ and sharing it!

---
