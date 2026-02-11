import requests
import re
from bs4 import BeautifulSoup

def extract_cves_from_url(url, mariadb_version):
    """
    Extract CVEs and their links for a given MariaDB version from a markdown-like web page.
    """
    response = requests.get(url)
    response.raise_for_status()
    text = response.text

    # Regex to capture CVE ID and link
    cve_pattern = re.compile(r"\[?(CVE-\d{4}-\d+)\]?\((https?://[^\)]+)\)")

    results = []
    for line in text.splitlines():
        if mariadb_version in line:
            print(line)
            match = cve_pattern.search(line)
            if match:
                cve_id, cve_link = match.groups()
                results.append({"cve": cve_id, "link": cve_link})

    return results


# Example usage
url = "https://mariadb.com/docs/server/security/securing-mariadb/security.md"
version = "MariaDB 11.4.9"
cves = extract_cves_from_url(url, version)

print(f"CVEs affecting {version}:")
for entry in cves:
    print(f"{entry['cve']} -> {entry['link']}")
