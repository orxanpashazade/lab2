import re
import json
from urllib.parse import urlparse

# Fayl yolları
log_file_path = "access_log.txt"
output_json_path = "summary_report.json"

# Qara siyahıdakı domenlər
blacklist = [
    "malicious-site.com",
    "blacklisteddomain.com",
    "phishingsite.org"
]

# Log faylından məlumat çıxarmaq üçün regex pattern
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<url>https?://[^\s"]+) HTTP/1.[01]" '
    r'(?P<status_code>\d{3}) (?P<error_code>\d+)'
)

def parse_log_file(file_path, blacklist):
    """Log faylını oxuyur və məlumatları təhlil edir."""
    alerts = []
    all_entries = []

    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                entry = {
                    "ip": match.group("ip"),
                    "timestamp": match.group("timestamp"),
                    "method": match.group("method"),
                    "url": match.group("url"),
                    "status_code": int(match.group("status_code")),
                    "error_code": int(match.group("error_code"))
                }
                all_entries.append(entry)

                # Qara siyahıdakı domenlərlə uyğunluq yoxlamaq
                url = entry["url"]
                for domain in blacklist:
                    if domain in url:
                        entry["blacklisted"] = True
                        alerts.append(entry)
                        break
                else:
                    entry["blacklisted"] = False

    return all_entries, alerts

# Log faylını təhlil etmək
all_entries, alerts = parse_log_file(log_file_path, blacklist)

# Hadisələrin status kodlarına görə sayını hesablamaq
status_counts = {}
for entry in all_entries:
    status_code = entry["status_code"]
    status_counts[status_code] = status_counts.get(status_code, 0) + 1

# JSON formatında məlumat hazırlamaq
output_data = {
    "total_entries": len(all_entries),
    "total_alerts": len(alerts),
    "status_counts": status_counts,
    "entries": all_entries,
    "alerts": alerts
}

# Nəticələri JSON faylına yazmaq
with open(output_json_path, "w") as json_file:
    json.dump(output_data, json_file, indent=4)

print(f"Ətraflı hesabat '{output_json_path}' faylına yazıldı.")