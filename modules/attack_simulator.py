# Q: Generate selected cyber attack logs

from datetime import datetime, timedelta


def generate_brute_force():
    logs = []
    base_time = datetime.now().replace(second=0, microsecond=0)
    ip = "192.168.1.10"
    user = "admin"

    for i in range(6):
        logs.append(f"[{(base_time + timedelta(seconds=i*5))}] LOGIN_FAILED IP={ip} USER={user}")

    return logs


def generate_multi_ip():
    logs = []
    base_time = datetime.now().replace(second=0, microsecond=0)
    user = "admin"

    ips = ["11.22.33.44", "22.33.44.55", "33.44.55.66"]

    for i, ip in enumerate(ips):
        logs.append(f"[{(base_time + timedelta(seconds=i*10))}] LOGIN_FAILED IP={ip} USER={user}")

    return logs


def generate_time_anomaly():
    logs = []
    odd_time = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)

    logs.append(f"[{odd_time}] LOGIN_SUCCESS IP=99.88.77.66 USER=admin")

    return logs


def generate_geo_anomaly():
    logs = []
    base_time = datetime.now().replace(second=0, microsecond=0)

    logs.append(f"[{base_time}] LOGIN_SUCCESS IP=192.168.1.10 USER=admin")
    logs.append(f"[{(base_time + timedelta(minutes=3))}] LOGIN_SUCCESS IP=33.44.55.66 USER=admin")

    return logs