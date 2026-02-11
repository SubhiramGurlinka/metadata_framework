import re
from models import Vulnerability
from utils.get_response import get_response_text
from utils.severity_rank import severity_rank
from utils.get_response import get_response_text
from strategies.base import PageParser

class MariaDbParser(PageParser):
    def get_severity(self, url):
        cve_page_text = get_response_text(url)
        match = re.search(r'"baseSeverity":\s*"([^"]+)"', cve_page_text)
        if match:
            return match.group(1).title()
        return "Unknown"

    def parse(self, url, context):
        try:
            release_date = context["release_date"]
            fix_version = context["product_fix_version"]

            all_cves = set()
            max_severity = "Unknown"
            text = get_response_text(url)
            # Regex to capture CVE ID and link
            cve_pattern = re.compile(r"\[?(CVE-\d{4}-\d+)\]?\((https?://[^\)]+)\)")

            for line in text.splitlines():
                if fix_version in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id, cve_link = match.groups()

                        # Actual cve_link needs JavaScript support, So got the JSON link
                        cve_link = f"https://cveawg.mitre.org/api/cve/{cve_id}"
                        all_cves.add(cve_id)
                        severity = self.get_severity(cve_link)
                        if severity_rank(severity) > severity_rank(max_severity):
                            max_severity = severity

            
            # 4. Return the Vulnerability object
            return [Vulnerability(
                cve_id=sorted(list(all_cves)),
                severity=max_severity,
                vendor="MariaDB",
                product=context.get("product", "MariaDB"),
                product_base_version=context.get("base_version"),
                product_fix_version=context.get("product_fix_version"),
                source_id=context.get("product_fix_version"),
                published_date=release_date if release_date else None
            )]

        except Exception as e:
            print(e)
            return []
