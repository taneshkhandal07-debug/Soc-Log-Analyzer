# Q: Detect suspicious login times (odd hours activity)

def detect_time_anomaly(logs, start_hour=0, end_hour=6):
    """
    Detects logins during unusual hours
    Default: 12 AM to 6 AM
    """

    suspicious_events = []

    for log in logs:
        hour = log["timestamp"].hour

        # Check only successful logins (important)
        if log["event"] == "LOGIN_SUCCESS":
            if start_hour <= hour < end_hour:
                suspicious_events.append({
                    "ip": log["ip"],
                    "user": log["user"],
                    "timestamp": log["timestamp"],
                    "type": "Time Anomaly",
                    "details": f"Login at {hour}:00 hours"
                })

    return suspicious_events