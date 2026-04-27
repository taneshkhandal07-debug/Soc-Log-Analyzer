# 🛡 SOC Threat Detection & Log Analyzer

🚀 **Live Demo:**
👉 https://soc-log-analyzer.streamlit.app/

---

## 🔥 Overview

A **cybersecurity-focused SOC (Security Operations Center) simulation platform** that analyzes log files, detects attack patterns, and provides actionable threat insights through an interactive dashboard.

This project replicates **real-world SOC workflows** including detection engineering, anomaly analysis, threat intelligence, and incident reporting.

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
