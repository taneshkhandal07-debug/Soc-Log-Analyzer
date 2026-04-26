# Q: Parse log file and convert it into structured data for analysis

import re
from datetime import datetime

def parse_log_line(line):
    pattern = r"\[(.*?)\]\s(\w+)\sIP=(.*?)\sUSER=(.*)"
    match = re.match(pattern, line)

    if match:
        timestamp_str, event, ip, user = match.groups()

        return {
            "timestamp": datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"),
            "event": event,
            "ip": ip,
            "user": user
        }
    return None


def parse_log_file(file_path):
    logs = []

    with open(file_path, "r") as file:
        for line in file:
            parsed = parse_log_line(line.strip())
            if parsed:
                logs.append(parsed)

    return logs