# Q: Generate incident reports based on detected threats

def generate_recommendation(threat_type, risk):
    """
    Suggest actions based on threat type and severity
    """

    if threat_type == "Brute Force":
        if risk == "High":
            return "Immediately block IP, enable MFA, investigate account compromise"
        elif risk == "Medium":
            return "Monitor IP, consider temporary block, enable MFA"

    elif threat_type == "Suspicious Login":
        if risk == "High":
            return "Force password reset, enable MFA, review account activity"
        elif risk == "Medium":
            return "Notify user, monitor account behavior"

    return "No immediate action required"


def generate_report(detections):
    """
    Generate structured incident report
    """

    report = []
    report.append("====== 🚨 SOC INCIDENT REPORT ======\n")

    for idx, item in enumerate(detections, start=1):
        recommendation = generate_recommendation(item["type"], item["risk"])

        report.append(f"Incident {idx}:")
        report.append(f"Type: {item['type']}")
        report.append(f"IP Address: {item['ip']}")
        report.append(f"Risk Level: {item['risk']}")

        # Optional fields depending on detection type
        if "attempts" in item:
            report.append(f"Failed Attempts: {item['attempts']}")

        if "failures_before_success" in item:
            report.append(f"Failures Before Success: {item['failures_before_success']}")

        report.append(f"Recommendation: {recommendation}")
        report.append("-" * 40)

    return "\n".join(report)