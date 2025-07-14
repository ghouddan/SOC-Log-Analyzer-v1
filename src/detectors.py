import json
from datetime import datetime, time

REGULAR_HOURS = {
    "start": time(hour=9, minute=0),  # 9:00 AM
    "end": time(hour=17, minute=0)    # 5:00 PM
}

def detect_brute_force(parsed_logs, threshold=5):
    """
    Detects brute force attacks in the parsed log data and saves the results to a JSON file.

    Args:
        parsed_log (list): List of dictionaries containing parsed log entries.
        threshold (int): Number of failed login attempts to consider as a brute force attack.
    """
    failed_logins = {}
    
    for entry in parsed_logs:
        is_failed_ssh = entry.get("process") == "sshd" and "Failed password" in entry.get("message", "")
        is_failed_windows = entry.get("EventID") == 4625

        if is_failed_ssh or is_failed_windows:
            ip = entry.get("src-ip") or entry.get("Hostname")
            if ip:
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

    alerts = []
    for ip, count in failed_logins.items():
        if count >= threshold:
            alerts.append({
                "ip_address": ip,
                "failed_attempts": count,
                "message": f"Potential brute force attack detected (>{threshold} failed attempts)."
            })
    return {"brute_force": alerts}

def detect_blacklist(parsed_logs, blacklist_file):
    """
    Detects if any IP address in the log file is blacklisted.
     
    Args:
        parsed_log (list): List of dictionaries containing parsed log entries.
        blacklist_file (str): Path to the file containing blacklisted IP addresses."""
    with open(blacklist_file, 'r') as f:
        blacklist = set(line.strip() for line in f if line.strip())

    alerts = []
    seen_ips = set()
    for entry in parsed_logs:
        ip = entry.get("src-ip") or entry.get("Hostname")
        if ip and ip in blacklist and ip not in seen_ips:
            alerts.append({
                "ip_address": ip,
                "message": "Blacklisted IP detected."
            })
            seen_ips.add(ip)
    return {"blacklist": alerts}

def detect_off_hours_login(parsed_logs):
    """
    Detects logins that occur outside of normal working hours.

    Args:
        parsed_log (list): List of dictionaries containing parsed log entries.

    """
    alerts = []
    seen_ips = set()

    for entry in parsed_logs:
        is_ssh = entry.get("process") == "sshd" and "Accepted password for" in entry.get("message", "")
        is_windows = entry.get("EventID") == 4624
        ip = entry.get("src-ip") or entry.get("Hostname")
        timestamp = entry.get("timestamp") or entry.get("EventTime")

        if not ip or ip in seen_ips:
            continue

        try:
            if is_ssh:
                ts = f"{datetime.now().year} {timestamp}"
                dt = datetime.strptime(ts, "%Y %b %d %H:%M:%S")
            elif is_windows:
                dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
            else:
                continue

            if dt.time() < REGULAR_HOURS["start"] or dt.time() > REGULAR_HOURS["end"]:
                alerts.append({
                    "timestamp": timestamp,
                    "ip_address": ip,
                    "message": "Login occurred outside regular working hours."
                })
                seen_ips.add(ip)
        except Exception as e:
            print(f"Timestamp parsing error: {timestamp} -> {e}")

    return {"off_hours": alerts}