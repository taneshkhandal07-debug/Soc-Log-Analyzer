# Q: Check if IPs are known malicious

def check_malicious_ips(detections):
    # Mock threat intelligence database
    malicious_ips = ["203.45.67.89", "45.23.67.89"]

    results = []

    for item in detections:
        if item["ip"] in malicious_ips:
            item["threat_intel"] = "Known Malicious IP"
            item["risk"] = "High"  # escalate risk
        else:
            item["threat_intel"] = "Clean"

        results.append(item)

    return results