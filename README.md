# 🛡 SOC Threat Detection & Log Analyzer

A **cybersecurity-focused SOC (Security Operations Center) simulation tool** that analyzes system logs, detects suspicious activities, and visualizes threats through an interactive dashboard.

Built with a focus on **real-world security workflows**, this project demonstrates detection engineering, anomaly analysis, and attack simulation.

---

## 🚀 Features

### 🔍 Threat Detection Engine

* Brute Force Attack Detection
* Suspicious Login Pattern Detection
* Multi-IP Attack Detection
* Time-based Anomaly Detection
* Geo-IP Anomaly Detection

---

### 🧠 Risk Intelligence

* Automated risk classification:

  * 🟢 Low
  * 🟡 Medium
  * 🔴 High
* Threat Intelligence enrichment (malicious IP detection)

---

### 🧪 Attack Simulator

* Generate synthetic attack logs for:

  * Brute Force
  * Multi-IP Attacks
  * Time Anomalies
  * Geo Anomalies
  * 🔥 Combined attack scenarios
* Enables testing and validation of detection pipeline

---

### 📊 Interactive Dashboard

* Clean SOC-style UI (Dark Cyber Theme)
* Tabs:

  * 📊 Overview
  * 🚨 Alerts
  * 📄 Logs
  * 🧾 Reports
* Real-time filtering:

  * By risk level
  * By attack type
* 🔍 Search functionality (IP/User)
* 📈 Attack timeline visualization

---

### 📄 Incident Reporting

* Auto-generated structured reports
* Includes:

  * Attack type
  * Risk level
  * Recommendations

---

## 🏗 Project Structure

```
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
│
├── data/
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone Repository

```
git clone https://github.com/<your-username>/soc-log-analyzer.git
cd soc-log-analyzer
```

---

### 2. Create Virtual Environment

```
python -m venv venv
venv\Scripts\activate
```

---

### 3. Install Dependencies

```
pip install -r requirements.txt
```

---

### 4. Run the App

```
streamlit run app.py
```

---

## 🧪 Usage

1. Upload a `.log` file
2. Select detection settings (sidebar)
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
* Attack Simulation & Validation

---

## 💡 Why This Project?

This project was built to simulate how modern security teams:

* Monitor logs
* Detect attacks
* Analyze suspicious behavior
* Respond to threats

It bridges the gap between **academic concepts and real-world cybersecurity practices**.

---

## 🚀 Future Enhancements

* Real-time log streaming
* Integration with external threat intelligence APIs
* Machine Learning-based anomaly detection
* User authentication & role-based access
* Deployment on cloud platforms

---

## 👨‍💻 Author

**Tanesh Khandal**

* 🎓 JECRC University
* 💻 Aspiring Cybersecurity & Tech Enthusiast

---

## ⭐ If you found this useful

Give this repo a ⭐ and feel free to fork & improve!

---
