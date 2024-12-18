import re
import json
from collections import Counter
from urllib.parse import urlparse

# Fayl yolları
log_file_path = "access_log.txt"
output_json_path = "alert.json"

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
    """Log faylını oxuyur və qara siyahıdakı domenlərlə uyğun gələn qeydləri toplayır."""
    alerts = []

    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                url = match.group("url")
                for domain in blacklist:
                    if domain in url:
                        entry = {
                            "ip": match.group("ip"),
                            "timestamp": match.group("timestamp"),
                            "method": match.group("method"),
                            "url": url,
                            "status_code": int(match.group("status_code")),
                            "error_code": int(match.group("error_code"))
                        }
                        alerts.append(entry)
                        break

    return alerts

def count_events_by_status(alerts):
    """Hadisələrin status kodlarına görə sayını hesablayır."""
    status_counts = Counter([alert["status_code"] for alert in alerts])
    return dict(status_counts)

# Qara siyahı ilə uyğun gələn qeydləri tapmaq
alerts = parse_log_file(log_file_path, blacklist)

# Status kodlarına görə hadisə sayını hesablamaq
status_counts = count_events_by_status(alerts)

# JSON formatında məlumat hazırlamaq
output_data = {
    "total_alerts": len(alerts),
    "status_counts": status_counts,
    "alerts": alerts
}

# Nəticələri JSON faylına yazmaq
with open(output_json_path, "w") as json_file:
    json.dump(output_data, json_file, indent=4)

print(f"Uyğun qara siyahıya alınmış URL-lər '{output_json_path}' faylına yazıldı.")