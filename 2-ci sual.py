import re
from collections import Counter

# Log faylını simulyasiya edək
log_content = """
192.168.1.100 - - [05/Dec/2024:09:15:10 +0000] "GET http://malicious-site.com/page1 HTTP/1.1" 404 4321
192.168.1.101 - - [05/Dec/2024:09:16:20 +0000] "GET http://example.com/page2 HTTP/1.1" 200 5432
192.168.1.102 - - [05/Dec/2024:09:17:30 +0000] "GET http://blacklisteddomain.com/page3 HTTP/1.1" 404 1234
192.168.1.103 - - [05/Dec/2024:09:18:40 +0000] "POST http://malicious-site.com/login HTTP/1.1" 404 2345
"""

# 404 status kodu ilə URL-ləri çıxarmaq üçün regex
regex_pattern = r'"(?:GET|POST|PUT|DELETE|HEAD) (http://[^\s]+) HTTP/[0-9.]+" 404'

# 404 status kodu ilə URL-ləri tapmaq
matches = re.findall(regex_pattern, log_content)

# Hər bir URL-in neçə dəfə göründüyünü hesabla
url_counts = Counter(matches)

# Nəticələri çap et
for url, count in url_counts.items():
    print(f"URL: {url}, Görünmə sayı: {count}")
