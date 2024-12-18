import re

# Jurnal faylının yolu
log_file_path = "access_log.txt"

# Nümunə qara siyahı (bu siyahını ehtiyacınıza görə dəyişdirə bilərsiniz)
blacklist = [
    "malicious-site.com",
    "blacklisteddomain.com",
    "phishingsite.org"
]

def extract_urls(log_content):
    """Jurnal mətnindən URL-ləri çıxarır."""
    url_pattern = r'https?://[^\s"]+'
    return re.findall(url_pattern, log_content)

def check_blacklisted_urls(urls, blacklist):
    """URL-ləri qara siyahıdakı domenlərlə müqayisə edir və uyğunluqları tapır."""
    matches = []
    for url in urls:
        for domain in blacklist:
            if domain in url:
                matches.append(url)
    return matches

# Jurnal faylını oxumaq
with open(log_file_path, "r") as file:
    log_content = file.read()

# URL-ləri çıxarmaq
urls = extract_urls(log_content)

# Qara siyahıdakı domenlərlə uyğunluqları tapmaq
blacklisted_urls = check_blacklisted_urls(urls, blacklist)

# Nəticələri göstərmək
if blacklisted_urls:
    print("Qara siyahıdakı domenlərlə uyğun gələn URL-lər:")
    for url in blacklisted_urls:
        print(url)
else:
    print("Qara siyahı ilə uyğun gələn URL tapılmadı.")