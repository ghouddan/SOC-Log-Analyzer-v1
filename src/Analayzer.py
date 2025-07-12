import argparse
from parser import parse_auth_log, parse_JSON_log  # Ensure parser.py exists in the same directory
from detectors import detect_brute_force, detect_blacklist # Ensure detectors.py exists in the same directory

parser = argparse.ArgumentParser(prog="Log_Analyzer" ,description="Parse log files and extract relevant information.")
parser.add_argument("--log_file", type=str, required=True, help="Path to the log file to analyze.")
parser.add_argument("--file_type", type=str, choices=["auth", "json"], required=True, help="Type of the file to parse; auth for .log file and json for .json file")
parser.add_argument("--output", type=str, default="result.json", help="Output file to save the parsed log data.")
parser.add_argument("--ip_list", type=str, help="Path to a file containing a list of IP addresses to filter log entries.")
parser.add_argument("--timestamp", type=str,required=False, help="Timestamp to filter log entries in the format 'YYYY-MM-DD HH:MM:SS'.")
parser.add_argument("--threshold", type=int,required=False, help="Threshold for detecting brute force attacks based on failed login attempts.", default=5)
args = parser.parse_args()

print(f"Analyzing log file: {args.log_file} of type {args.file_type}...")

if args.file_type == "auth":
    auth_log = parse_auth_log(args.log_file)
    detect_brute_force(auth_log,args.output, threshold=args.threshold)
    detect_blacklist(args.ip_list,auth_log)

elif args.file_type == "json":
    json_log = parse_JSON_log(args.log_file)
    detect_brute_force(json_log, args.output, threshold=args.threshold)
else:
        print("Unsupported file type. Please use 'auth' for .log- files or 'json' for .json files.")
