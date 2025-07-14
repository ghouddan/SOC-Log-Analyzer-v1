# SOC Log Analyzer

A lightweight simple Python tool designed to help in detecting common security events from system logs.

This tool supports both Unix/Linux auth.log files and structured Windows-style JSON logs. It performs basic threat detections such as brute force login attempts, blacklisted IP access, and off-hours logins.

## Features

- Brute Force Detection

    - Detects repeated failed login attempts from the same IP

- Blacklist Detection

    - Flags IP addresses present in a custom blacklist file

- Off-Hours Login Detection

    - Identifies logins outside normal working hours (9AM–5PM)

- Supports Multiple Log Formats

    - Unix/Linux auth.log

    - JSON logs from Windows Event Viewer

## How to Use

```
python analyzer.py --log_file ./samples/auth.log --file_type auth --output report.json --threshold 5 --timestamp --ip_list blacklist.txt
```

Output Format

## Output is saved as JSON with structure:

```
{
  "brute_force": [ ... ],
  "blacklist": [ ... ],
  "off_hours": [ ... ]
}
```

## Sample Use Cases

- Detect SSH brute-force attacks on Linux

- Flag logins from known malicious IPs

- Monitor user behavior outside normal working hours

## Logs Tested

/var/log/auth.log (Ubuntu/Debian)

Exported JSON from Windows Event Viewer (4624/4625)

Motivation

This project was built to simulate the kind of log analysis performed in real SOC environments and to gain hands-on practice with log parsing and threat detection. It’s part of my learning journey in cybersecurity.


📫 LinkedIn | 🛡️ Cybersecurity Enthusiast | 💻 Software Engineer

