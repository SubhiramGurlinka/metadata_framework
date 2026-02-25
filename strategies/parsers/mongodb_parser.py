import re
from packaging.version import Version, InvalidVersion
from utils.get_soup import get_soup

URL = "https://www.mongodb.com/about/alerts/"
mongodb_soup = get_soup(URL, "html.parser")
cve_div = mongodb_soup.find(
    "p", 
    string=lambda s: s and ("Common Vulnerabilities and Exposures (CVEs)" in s)
)
print(cve_div)

next_section = cve_div.find_next("section")
next_div = next_section.find("div")
# print(next_div)
for div in next_div.find_all("div"):
    print(div)
    break
