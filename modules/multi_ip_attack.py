# Q: Detect multiple IPs targeting the same user within a short time window

from collections import defaultdict
from datetime import timedelta


def detect_multi_ip_attack(logs, threshold=3, time_window=120):
    """
    Detects if multiple IPs are trying to access the same user account
    threshold = number of unique IPs
    time_window = seconds
    """

    user_activity = defaultdict(list)
    suspicious_events = []

    # Collect failed login attempts per user
    for log in logs:
        if log["event"] == "LOGIN_FAILED":
            user_activity[log["user"]].append((log["timestamp"], log["ip"]))

    # Analyze each user
    for user, events in user_activity.items():
        events.sort()

        for i in range(len(events)):
            unique_ips = set()
            start_time = events[i][0]

            for j in range(i, len(events)):
                current_time, ip = events[j]

                if (current_time - start_time) <= timedelta(seconds=time_window):
                    unique_ips.add(ip)

                    if len(unique_ips) >= threshold:
                        suspicious_events.append({
                            "ip": "Multiple",
                            "user": user,
                            "ip_count": len(unique_ips),
                            "type": "Multi-IP Attack",
                            "details": f"{len(unique_ips)} IPs targeting user within {time_window} seconds"
                        })
                        break
                else:
                    break

    return suspicious_events