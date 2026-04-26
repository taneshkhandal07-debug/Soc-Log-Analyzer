# Q: Assign risk levels to detected threats

def assign_risk(detections):
    """
    Takes detected events and assigns risk levels
    """

    results = []

    for item in detections:
        risk = "Low"

        # Brute Force Risk Logic
        if item["type"] == "Brute Force":
            if item["attempts"] >= 10:
                risk = "High"
            elif item["attempts"] >= 5:
                risk = "Medium"

        # Suspicious Login Risk Logic
        elif item["type"] == "Suspicious Login":
            if item["failures_before_success"] >= 5:
                risk = "High"
            else:
                risk = "Medium"
        #Time Anomaly Risk Logic
        elif item["type"] == "Time Anomaly":
            risk = "Medium"
        # Multi-IP Attack Risk Logic
        elif item["type"] == "Multi-IP Attack":
            if item["ip_count"] >= 5:
                risk = "High"
            else:
                risk = "Medium"
        # Geo-IP Anomaly Risk Logic
        elif item["type"] == "Geo Anomaly":
            risk = "High"

        item["risk"] = risk
        results.append(item)

    return results