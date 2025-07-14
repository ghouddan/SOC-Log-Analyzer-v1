import argparse
import json
from log_parser import parse_auth_log, parse_JSON_log
from detectors import detect_brute_force, detect_blacklist, detect_off_hours_login

def main():
    parser = argparse.ArgumentParser(description="Parse authentication log files and extract relevant information about brute force attempt, blacklisted IP addresses presence and out of hour login.")
    parser.add_argument("--log", required=True, help="Path to the log file to analyze.")
    parser.add_argument("--type", choices=["auth", "json"], required=True, help="Type of the file to parse; 'auth' for auth.log and 'json' for JSON log files.")
    parser.add_argument("--output", default="report.json", help="Output file to save the analysis report.")
    parser.add_argument("--ip_list",type=str, help="Path to blacklisted IPs")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for detecting brute force attacks based on failed login attempts.")
    parser.add_argument("--timestamp", action="store_true", help="Include timestamps in the analysis for off hour login detection.")
    args = parser.parse_args()

    if args.file_type == "auth":
        logs = parse_auth_log(args.log_file)
    else:
        logs = parse_JSON_log(args.log_file)

    report = {}
    report.update(detect_brute_force(logs, args.threshold))

    if args.ip_list:
        report.update(detect_blacklist(logs, args.ip_list))

    if args.timestamp:
        report.update(detect_off_hours_login(logs))

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=4)

    print(f"Analysis complete. Report saved to {args.output}.")


if __name__ == "__main__":
    main()