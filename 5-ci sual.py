from bs4 import BeautifulSoup

# HTML faylını oxuyun
input_file = "threat_feed.html"
output_file = "updated_threat_feed.html"

with open(input_file, "r", encoding="utf-8") as file:
    soup = BeautifulSoup(file, "html.parser")

# Qara siyahıya alınmış domenləri göstərən <li> elementlərini silin
for li in soup.find_all("li"):
    li.decompose()

# Yenilənmiş HTML-i fayla yazın
with open(output_file, "w", encoding="utf-8") as file:
    file.write(str(soup))

print(f"Yenilənmiş HTML: '{output_file}'")