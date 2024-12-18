import re

# Log faylını simulyasiya edək
log_content = """
192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] "GET http://malicious-site.com/page1 HTTP/1.1" 404 4321
192.168.1.101 - - [05/Dec/2024:09:16:20 +0000] "GET http://example.com/page2 HTTP/1.1" 200 5432
192.168.1.102 - - [05/Dec/2024:09:17:30 +0000] "GET http://blacklisteddomain.com/page3 HTTP/1.1" 404 1234
192.168.1.103 - - [05/Dec/2024:09:18:40 +0000] "POST http://malicious-site.com/login HTTP/1.1" 404 2345
"""

# URL-ləri və status kodlarını çıxarmaq üçün regex
regex_pattern = r'"(?:GET|POST|PUT|DELETE|HEAD) (http://[^\s]+) HTTP/[0-9.]+" (\d{3})'

# Uyğunluqları tapmaq
matches = re.findall(regex_pattern, log_content)

# Nəticələri fayla yazmaq
output_file = "url_status_report.txt"

with open(output_file, "w", encoding="utf-8") as file:
    file.write("URL və Status Kodları\n")
    file.write("=======================\n")
    for url, status_code in matches:
        file.write(f"URL: {url}, Status Code: {status_code}\n")

print(f"URL-lər və status kodları '{output_file}' adlı fayla yazıldı.")
