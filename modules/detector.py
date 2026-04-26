# Q: Detect brute force attacks and suspicious login behavior

from collections import defaultdict
from datetime import timedelta


def detect_brute_force(logs, threshold=5, time_window=60):
    """
    Detects brute force attacks based on failed login attempts
    threshold = number of attempts
    time_window = seconds
    """

    failed_attempts = defaultdict(list)
    suspicious_ips = []

    for log in logs:
        if log["event"] == "LOGIN_FAILED":
            failed_attempts[log["ip"]].append(log["timestamp"])

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            for j in range(i + 1, len(timestamps)):
                if (timestamps[j] - timestamps[i]) <= timedelta(seconds=time_window):
                    count += 1

                    if count >= threshold:
                        suspicious_ips.append({
                            "ip": ip,
                            "attempts": count,
                            "type": "Brute Force"
                        })
                        break
                else:
                    break

    return suspicious_ips


def detect_suspicious_success(logs):
    """
    Detects login success after multiple failures
    """

    failed_count = defaultdict(int)
    suspicious_events = []

    for log in logs:
        ip = log["ip"]

        if log["event"] == "LOGIN_FAILED":
            failed_count[ip] += 1

        elif log["event"] == "LOGIN_SUCCESS":
            if failed_count[ip] >= 3:
                suspicious_events.append({
                    "ip": ip,
                    "failures_before_success": failed_count[ip],
                    "type": "Suspicious Login"
                })

            failed_count[ip] = 0  # reset after success

    return suspicious_events