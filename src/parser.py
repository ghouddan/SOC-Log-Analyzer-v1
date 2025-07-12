import re
import json

parsed_log = []
def parse_auth_log(log_file_path):
    """
    Parses the auth.log file and returns a list of dictionaries with structured log entries.
    
    Each dictionary contains:
    - timestamp: The date and time of the log entry.
    - hostname: The hostname from which the log entry originated.
    - process: The process name that generated the log entry.
    - pid: The process ID (if available).
    - message: The actual log message.
    
    Returns:
        List[Dict[str, str]]: A list of parsed log entries.
    """
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\d\.-]+)\s+([\w\d\.-]+)(?:\[(\d+)\])?:\s+(.*)', line)
            if match:
                timestamp, hostname, process, pid, message = match.groups()
                log_entry = {
                    "timestamp": timestamp,
                    "Hostname": hostname,
                    "process" : process,
                    "src-ip": re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message).group() if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message) else None,                    "pid": pid,
                    "message": message
                }
                parsed_log.append(log_entry)
        return parsed_log
    
def parse_JSON_log(log_file_path):
        """
        Parses a JSON log file and returns a list of dictionaries with structured log entries.
        
        Each dictionary contains:
        - timestamp: The date and time of the log entry.
        - hostname: The hostname from which the log entry originated.
        - process: The process name that generated the log entry.
        - pid: The process ID (if available).
        - message: The actual log message.
        
        Returns:
            List[Dict[str, str]]: A list of parsed log entries.
        """
        with open(log_file_path) as file:
            for line in file:
                try:
                    log_entry = json.loads(line)
                    parsed_log.append(log_entry)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")
            return parsed_log




if __name__ == "__main__":
    log_file_path ="/home/mo/Desktop/SOC-Log-Analyzer-v1/data/auth.log"
    parsed_esntries=parse_auth_log(log_file_path)
    for entry in parsed_esntries:
        print(entry)
    