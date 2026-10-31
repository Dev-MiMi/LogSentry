from datetime import datetime


try:
    with open('samples/auth.log') as file_object:

        failed_logins = {}
        count_failed = 0
        current_year = datetime.now().year
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
