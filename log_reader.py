from datetime import datetime
import argparse


# The learning script now requires a real input path rather than demo data.
parser = argparse.ArgumentParser(description="Learning script for traditional SSH log timestamps.")
parser.add_argument("log_file", help="Path to an existing authentication log")
parser.add_argument("--year", required=True, type=int, help="Starting year of the log")
arguments = parser.parse_args()


try:
    with open(arguments.log_file) as file_object:

        failed_logins = {}
        count_failed = 0
        current_year = arguments.year
        failed_times = {}

        for line in file_object:
            if "Failed password" in line:
                count_failed += 1
                words = line.split()
                timestamp = " ".join(words[0:3])
                event_time = datetime.strptime(
                    f"{current_year} {timestamp}",
                    "%Y %b %d %H:%M:%S"
                )
                position = words.index("from")
                position += 1
                ip = words[position]
                if ip in failed_times:
                    failed_times[ip].append(event_time)
                else:
                    failed_times[ip] = [event_time]
                print(f"{event_time} - {ip}")
                if ip in failed_logins:
                    failed_logins[ip] += 1
                else:
                    failed_logins[ip] = 1
        for ip, times in failed_times.items():
            print(ip, times)
        for ip, count in failed_logins.items():
            if count >= 5:
                print(f"ALERT: Possible brute-force attack from {ip}")

            if count == 1:
                print(f"{ip}: {count} failed login")
            else:
                print(f"{ip}: {count} failed logins")

        print(f"Total failed logins: {count_failed}")

except FileNotFoundError:
    print("file is not found")
