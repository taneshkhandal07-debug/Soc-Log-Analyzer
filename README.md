# 🛡️ SOC Threat Detection & Log Analyzer

**🚀 [Live Demo](https://soc-log-analyzer.streamlit.app/)**

Security analysts spend a disproportionate share of their day manually scanning log files for threats — a slow, repetitive process that contributes to alert fatigue and delays real incident response. This project automates the first-pass triage (parsing, anomaly detection, risk scoring, and report drafting) so analysts can spend their time on judgment calls and investigation instead of manual log review.

It's an augmentation tool, not a replacement for analyst judgment — the system surfaces and prioritizes what's worth a human's attention; it doesn't make the final call.

---

## Who this is for

Built primarily for **security analysts** dealing with alert fatigue and high log volumes who need help prioritizing what actually matters, and secondarily for **cybersecurity students** who want hands-on exposure to SOC detection workflows without needing access to a real production environment or real attack data.

---

## ⚡ Key Features

### 🔍 Threat Detection Engine
Logs are parsed into structured security events, then checked against five detection types:
- Brute Force Attack Detection
- Suspicious Login Pattern Detection
- Multi-IP Attack Detection
- Time-Based Anomaly Detection
- Geo-IP Anomaly Detection

### 🧠 Risk & Threat Intelligence
Every detected event is automatically scored so analysts can triage by severity instead of reading every alert in order:
- 🟢 Low &nbsp; 🟡 Medium &nbsp; 🔴 High

Suspicious IPs are also enriched against threat intelligence data to flag known-malicious sources — adding context an analyst would otherwise have to look up manually.

### 🧪 Smart Attack Simulator
Generates synthetic logs for testing detection logic without needing real attack data:
- Brute Force
- Multi-IP Attacks
- Time Anomalies
- Geo Anomalies
- Combined attack scenarios

Useful both for validating the detection pipeline and for the student/training use case.

### 📊 Analytics Dashboard
A live, cyber-themed view across four tabs, so the analyst doesn't have to leave one screen to investigate:
- 📊 Overview
- 🚨 Alerts
- 📄 Logs
- 🧾 Reports

**Visualizations include:** top attacking IPs, attack timeline, attack frequency heatmap, and user activity tracking.

### 📤 Export & Reporting
- 📄 Incident report (TXT)
- 📥 Incident report (PDF)
- 📤 Filtered logs (JSON)

---

## Product Decisions

A few calls made deliberately when scoping v1, rather than just "what I had time to build":

**Rule-based detection over ML, for now.** Thresholds and pattern rules are transparent and easy to tune — important for a security tool, where an analyst needs to trust *why* something was flagged. ML-based detection is scoped for a later phase once there's enough labeled data to validate it properly.

**No real-time streaming in v1.** Log upload is batch-based rather than live-streamed. This was a conscious scope cut to ship a working detection pipeline first, with real-time monitoring planned as a Phase 2 addition rather than blocking v1 on it.

**No multi-user auth/RBAC yet.** Acceptable for a single-analyst workflow and for the portfolio/training use case, but flagged as a gap before this could be used by an actual team — role-based access is on the roadmap.

**False positives vs. false negatives were treated as different risk levels**, not just "errors to minimize evenly." Missed detections (false negatives) were treated as higher-impact than over-flagging (false positives), since under-detecting a real threat is more costly than an analyst dismissing a false alarm — this shaped how detection thresholds were tuned.

**File upload validation was treated as a security requirement, not an edge case** — uploaded files are sanitized and validated, since a tool meant to analyze attacks shouldn't itself be an attack vector.

**Deliberately out of scope for v1:** real-time log streaming, SIEM integration, ML-based detection, role-based access control, external threat intel APIs — all roadmapped for later phases rather than cut entirely.

---

## How Success Was Defined

Rather than just "does it run," the project was scoped against:
- Detection accuracy and alert generation time
- Report generation time
- Volume of logs successfully analyzed
- High-risk events correctly identified

---

## 🏗️ Project Structure

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
│   └── pdf_report.py
│
├── data/
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/taneshkhandal07-debug/Soc-Log-Analyzer.git
cd Soc-Log-Analyzer
```

**2. Create a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the application**
```bash
streamlit run app.py
```

---

## 🧪 How to Use

1. Upload a `.log` file
2. Select detection settings
3. *(Optional)* Generate attack logs using the simulator
4. Analyze alerts, risk levels, timeline, and reports

---

## 🎯 Key Concepts Demonstrated

Security log analysis · Anomaly detection · SOC workflow simulation · Threat intelligence integration · Data visualization & analytics · Attack simulation & validation

---

## 🛠️ Tech Stack

**Backend:** Python &nbsp;|&nbsp; **Frontend/Dashboard:** Streamlit &nbsp;|&nbsp; **Data Processing:** Pandas, NumPy &nbsp;|&nbsp; **Visualization:** Plotly &nbsp;|&nbsp; **Reporting:** PDF generation libraries

---

## 🚀 Future Enhancements

- Real-time log streaming
- Machine learning-based anomaly detection
- Integration with external threat intelligence APIs
- Role-based authentication system
- Cloud deployment scaling

---

## 👨‍💻 Author

**Tanesh Khandal**
🎓 JECRC University — Cybersecurity & Tech Enthusiast

---

## ⭐ Support

If you found this project useful, consider giving it a star and sharing it!


---
