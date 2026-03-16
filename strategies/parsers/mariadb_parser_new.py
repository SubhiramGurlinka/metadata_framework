import requests
import re
from dateutil import parser

def format_date(date: str) -> str:
        dt = parser.parse(date)
        return dt.strftime("%Y-%m-%d")

def get_release_date(date_url):
    r = requests.get(date_url, timeout=10)
    r.raise_for_status()

    for line in r.text.splitlines():
        if "Release date" in line.strip():
            match = re.search(r"Release date.*?(\d{1,2}\s+\w+\s+\d{4})", line)
            if match:
                return format_date(match.group(1))
    return

def get_security_cves(md_url):
    r = requests.get(md_url, timeout=30)
    r.raise_for_status()

    lines = r.text.splitlines()

    in_security_section = False
    results = []

    cve_pattern = re.compile(r'\[(CVE-\d{4}-\d+)\]\((https?://[^)]+)\)')

    for line in lines:

        # detect start of Security section
        if line.strip().startswith("### Security"):
            in_security_section = True
            continue

        # stop when next section begins
        if in_security_section and line.startswith("###"):
            break

        if in_security_section:
            match = cve_pattern.search(line)
            if match:
                results.append({
                    "cve": match.group(1),
                    "link": match.group(2)
                })

    return results


# url = "https://mariadb.com/docs/release-notes/community-server/10.11/10.11.12.md"

# print(get_security_cves(url))

date_url = "https://mariadb.com/docs/release-notes/community-server/changelogs/10.11/10.11.15.md"
print(get_release_date(date_url))