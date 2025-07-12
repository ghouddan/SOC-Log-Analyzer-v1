import json

def detect_brute_force(parsed_log, output_file="result.json", threshold=5):
    """
    Detects brute force attacks in the parsed log data and saves the results to a JSON file.

    Args:
        parsed_log (list): List of dictionaries containing parsed log entries.
        output_file (str): Path to the output JSON file.
        threshold (int): Number of failed login attempts to consider as a brute force attack.
    """
    failed_logins = {}

    for entry in parsed_log:
        is_failed_ssh = entry.get("process") == "sshd" and "Failed password" in entry.get("message", "")
        is_failed_windows = entry.get("EventID") == 4625

        if is_failed_ssh:
            ip_address = entry.get("src-ip") 
            failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1
    
        elif  is_failed_windows:
            ip_address = entry.get("hostname")  # Assuming hostname contains the IP address in Windows logs
            failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

    brute_force_alerts = [] 
    for ip, count in failed_logins.items():
        if count >= threshold:
            print(f"Brute force attack detected from IP: {ip} with {count} failed attempts.")
            alert = {
                "ip_address": ip,
                "failed_attempts": count,
                "message": f"Potential brute force attack detected. Failed attempts exceeded threshold of {threshold}."
            }
            brute_force_alerts.append(alert)

    # Save the brute force detection results to a JSON file
    if brute_force_alerts:
        with open(output_file, 'w') as f:
            json.dump(brute_force_alerts, f, indent=4)
        print(f"Brute force detection results saved to {output_file}.")
    else:
        print("No brute force attacks detected.")
        
    return output_file

black_list = []
ip_address = []
def detect_blacklist(blacklist_file, log_file):
    """
    Detects if any IP address in the log file is blacklisted.
    """
    # Placeholder for blacklist detection logic
    with open(blacklist_file, 'r') as f:
        for line in f:
          black_list.append(line.strip())
    for entry in log_file:
        current_ip = entry.get("src-ip")
        if current_ip in ip_address:
            continue
        if current_ip in black_list:
            print(f"Blacklisted IP detected: {entry.get('src-ip')}")
            ip_address.append(entry.get("src-ip"))
            print(ip_address)
    with open("result.json", 'a')as f:
        json.dump({"blacklisted_ips": ip_address}, f, indent=4)


        








def detect_of_hours_login():
    """
    Detects logins that occur outside of normal working hours.
    """
    # Placeholder for out-of-hours login detection logic
    pass


if __name__ == "__main__":
    # Example usage
    example_log = [
       {
  "EventID": 4625,
  "EventTime": "2023-10-01T14:30:00Z",
  "Source": "Microsoft-Windows-Security-Auditing",
  "ComputerName": "MyComputer",
  "User ": {
    "AccountName": "user123",
    "Domain": "MYDOMAIN",
    "LogonType": 3
  },
  "FailureReason": "Unknown user name or bad password.",
  "IP": "192.168.1.10",
  "WorkstationName": "Workstation1",
  "ProcessInformation": {
    "ProcessID": 1234,
    "ProcessName": "LogonUI.exe"
  },
  "AdditionalInformation": {
    "AuthenticationPackage": "Negotiate",
    "LogonGuid": "{00000000-0000-0000-0000-000000000000}"
  }
}

    ]
    detect_brute_force(example_log, "brute_force_result.json",1)  