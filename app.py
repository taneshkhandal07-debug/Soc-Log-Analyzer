# Q: Final SOC Dashboard with Advanced Features + Cyber UI

import streamlit as st
import pandas as pd
import json
import seaborn as sns
import matplotlib.pyplot as plt

from modules.parser import parse_log_file
from modules.detector import detect_brute_force, detect_suspicious_success
from modules.risk_engine import assign_risk
from modules.reporter import generate_report
from modules.threat_intel import check_malicious_ips
from modules.time_anomaly import detect_time_anomaly
from modules.multi_ip_attack import detect_multi_ip_attack
from modules.geo_ip import detect_geo_anomaly
from modules.pdf_report import generate_pdf

from modules.attack_simulator import (
    generate_brute_force,
    generate_multi_ip,
    generate_time_anomaly,
    generate_geo_anomaly
)

# ------------------ SESSION STATE ------------------
if "logs" not in st.session_state:
    st.session_state.logs = None

if "uploaded" not in st.session_state:
    st.session_state.uploaded = False

# ------------------ PAGE CONFIG ------------------
st.set_page_config(page_title="SOC Log Analyzer", layout="wide")

# ------------------ CYBER UI ------------------
st.markdown("""
<style>
body {background-color: #0E1117; color: #FAFAFA;}

.stTabs [role="tab"] {
    font-size: 20px;
    padding: 12px 24px;
    margin-right: 10px;
    border-radius: 10px;
    background-color: #1c1f26;
}

.stTabs [aria-selected="true"] {
    background-color: #B22222;
    color: white;
    font-weight: bold;
}

.stTabs [role="tab"]:hover {
    background-color: #922B21;
    color: white;
}

.metric-card {
    background-color: #1c1f26;
    padding: 20px;
    border-radius: 15px;
    text-align: center;
    border: 1px solid #2c2f36;
}

.stButton>button {
    border-radius: 10px;
    background-color: #B22222;
    color: white;
}

.stButton>button:hover {
    background-color: #922B21;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡 SOC Threat Detection Dashboard")

# ------------------ SIDEBAR ------------------
st.sidebar.title("⚙️ Detection Settings")

enable_brute = st.sidebar.checkbox("Brute Force Detection", True)
enable_suspicious = st.sidebar.checkbox("Suspicious Login Detection", True)
enable_time_anomaly = st.sidebar.checkbox("Time Anomaly Detection", True)
enable_multi_ip = st.sidebar.checkbox("Multi-IP Attack Detection", True)
enable_geo = st.sidebar.checkbox("Geo-IP Anomaly Detection", True)
enable_threat_intel = st.sidebar.checkbox("Threat Intelligence Check", True)

# ------------------ FILE UPLOAD ------------------
st.subheader("📂 Upload Log File (Required First)")

uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])

if uploaded_file:
    with open("data/uploaded.log", "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.session_state.logs = parse_log_file("data/uploaded.log")
    st.session_state.uploaded = True

    st.success("✅ File uploaded successfully")

# ------------------ ATTACK SIMULATOR ------------------
st.subheader("🧪 Attack Simulator")

attack_type = st.selectbox(
    "Select Attack Type",
    ["All Attacks", "Brute Force", "Multi-IP Attack", "Time Anomaly", "Geo Anomaly"]
)

col1, col2 = st.columns(2)

with col1:
    if st.button("⚡ Generate Attack Logs"):
        if not st.session_state.uploaded:
            st.error("❌ Upload a file first")
            st.stop()

        if attack_type == "All Attacks":
            logs_data = (
                generate_brute_force()
                + generate_multi_ip()
                + generate_time_anomaly()
                + generate_geo_anomaly()
            )
            filename = "data/all_attacks.log"

        elif attack_type == "Brute Force":
            logs_data = generate_brute_force()
            filename = "data/brute_force.log"

        elif attack_type == "Multi-IP Attack":
            logs_data = generate_multi_ip()
            filename = "data/multi_ip.log"

        elif attack_type == "Time Anomaly":
            logs_data = generate_time_anomaly()
            filename = "data/time_anomaly.log"

        else:
            logs_data = generate_geo_anomaly()
            filename = "data/geo_anomaly.log"

        with open(filename, "w") as f:
            for line in logs_data:
                f.write(line + "\n")

        st.session_state.logs = parse_log_file(filename)
        st.success("✅ Attack logs generated")

with col2:
    if st.button("🧹 Clear Logs"):
        st.session_state.logs = None
        st.session_state.uploaded = False
        st.success("Logs cleared")

# ------------------ MAIN DASHBOARD ------------------
if st.session_state.logs:

    logs = st.session_state.logs

    all_detections = []

    if enable_brute:
        all_detections += detect_brute_force(logs)

    if enable_suspicious:
        all_detections += detect_suspicious_success(logs)

    if enable_time_anomaly:
        all_detections += detect_time_anomaly(logs)

    if enable_multi_ip:
        all_detections += detect_multi_ip_attack(logs)

    if enable_geo:
        all_detections += detect_geo_anomaly(logs)

    risk_results = assign_risk(all_detections)

    if enable_threat_intel:
        risk_results = check_malicious_ips(risk_results)

    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview",
        "🚨 Alerts",
        "📄 Logs",
        "🧾 Reports"
    ])

    # ------------------ OVERVIEW ------------------
    with tab1:
        st.subheader("📊 Summary")

        total = len(risk_results)
        high = sum(1 for x in risk_results if x["risk"] == "High")
        medium = sum(1 for x in risk_results if x["risk"] == "Medium")

        col1, col2, col3 = st.columns(3)

        col1.markdown(f"<div class='metric-card'><h2>{total}</h2><p>Total Threats</p></div>", unsafe_allow_html=True)
        col2.markdown(f"<div class='metric-card'><h2>{high}</h2><p>High Risk</p></div>", unsafe_allow_html=True)
        col3.markdown(f"<div class='metric-card'><h2>{medium}</h2><p>Medium Risk</p></div>", unsafe_allow_html=True)

        # 🔥 Top IPs
        st.subheader("🔥 Top Attacking IPs")

        df = pd.DataFrame(risk_results)
        if not df.empty:
            top_ips = df["ip"].value_counts().head(5)
            st.bar_chart(top_ips)

    # ------------------ ALERTS ------------------
    with tab2:
        st.subheader("🚨 Threat Alerts")

        search = st.text_input("🔍 Search by IP/User")

        col1, col2 = st.columns(2)
        risk_filter = col1.selectbox("Risk", ["All", "High", "Medium", "Low"])
        type_filter = col2.selectbox("Type", ["All"] + list(set([x["type"] for x in risk_results])))

        filtered = risk_results

        if risk_filter != "All":
            filtered = [x for x in filtered if x["risk"] == risk_filter]

        if type_filter != "All":
            filtered = [x for x in filtered if x["type"] == type_filter]

        if search:
            filtered = [
                x for x in filtered
                if search.lower() in str(x.get("ip", "")).lower()
                or search.lower() in str(x.get("user", "")).lower()
            ]

        for item in filtered:
            msg = f"IP: {item['ip']} | Type: {item['type']} | Risk: {item['risk']}"
            if item["risk"] == "High":
                st.error(msg)
            elif item["risk"] == "Medium":
                st.warning(msg)
            else:
                st.info(msg)

        # 🔥 Export filtered logs
        if filtered:
            st.download_button(
                "📤 Export Filtered Logs",
                data=json.dumps(filtered, indent=2, default=str),
                file_name="filtered_logs.json"
            )

    # ------------------ LOGS ------------------
    with tab3:
        st.subheader("📄 Raw Logs")

        df_logs = pd.DataFrame(logs)
        st.dataframe(df_logs, use_container_width=True)

        df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"])

        st.subheader("📈 Timeline")
        timeline = df_logs.groupby(df_logs["timestamp"].dt.minute).size()
        st.line_chart(timeline)

        # 🔥 Heatmap
        st.subheader("🔥 Attack Heatmap")

        df_logs["hour"] = df_logs["timestamp"].dt.hour
        df_logs["minute"] = df_logs["timestamp"].dt.minute

        heatmap_data = df_logs.pivot_table(index="hour", columns="minute", aggfunc="size", fill_value=0)

        fig, ax = plt.subplots()
        sns.heatmap(heatmap_data, ax=ax)
        st.pyplot(fig)

        # 🔥 User activity
        st.subheader("👤 User Activity")

        if "user" in df_logs.columns:
            st.bar_chart(df_logs["user"].value_counts())

    # ------------------ REPORT ------------------
    with tab4:
        st.subheader("🧾 Incident Report")

        report = generate_report(risk_results)
        st.text_area("Report Output", report, height=300)

        # PDF download
        if st.button("📥 Download PDF Report"):
            file_path = generate_pdf(report)
            with open(file_path, "rb") as f:
                st.download_button("Download PDF", f, "soc_report.pdf")

        # TXT download
        st.download_button("📄 Download TXT Report", report, "soc_report.txt")

else:
    st.info("👆 Upload a log file to begin")