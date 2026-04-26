# Q: Detect impossible travel using IP → Country mapping

from collections import defaultdict
from datetime import timedelta

# Mock IP to Country mapping (replace with API later)
IP_COUNTRY_MAP = {
    "192.168.1.10": "India",
    "99.88.77.66": "India",
    "11.22.33.44": "USA",
    "22.33.44.55": "Germany",
    "33.44.55.66": "Russia",
}


def get_country(ip):
    return IP_COUNTRY_MAP.get(ip, "Unknown")


def detect_geo_anomaly(logs, time_window=300):
    """
    Detects if same user logs in from different countries in short time
    """

    user_logins = defaultdict(list)
    suspicious_events = []

    # Only successful logins matter
    for log in logs:
        if log["event"] == "LOGIN_SUCCESS":
            country = get_country(log["ip"])
            user_logins[log["user"]].append((log["timestamp"], country, log["ip"]))

    # Analyze per user
    for user, events in user_logins.items():
        events.sort()

        for i in range(len(events)):
            t1, c1, ip1 = events[i]

            for j in range(i + 1, len(events)):
                t2, c2, ip2 = events[j]

                if (t2 - t1) <= timedelta(seconds=time_window):
                    if c1 != c2 and c1 != "Unknown" and c2 != "Unknown":
                        suspicious_events.append({
                            "ip": f"{ip1} → {ip2}",
                            "user": user,
                            "type": "Geo Anomaly",
                            "details": f"{c1} → {c2} within {time_window} sec"
                        })
                        break
                else:
                    break

    return suspicious_events