# mariadb_parser.py

import re
import asyncio
from models import Vulnerability
from utils.get_page import get_response_text
from utils.severity_rank import severity_rank
from utils.get_severity import CVESeverityService
from strategies.base import PageParser

class MariaDbParser(PageParser):

    def parse(self, url, context):
        try:
            release_date = context.get("release_date")
            fix_version = context.get("product_fix_version")

            all_cves = set()
            max_severity = ""
            text = get_response_text(url)

            # Url fetching error
            if not text:
                return 
            
            # Regex to capture CVE ID and link
            cve_pattern = re.compile(r"\[?(CVE-\d{4}-\d+)\]?")

            for line in text.splitlines():
                if fix_version in line:
                    match = cve_pattern.search(line)
                    if match:
                        cve_id = match.group(1)
                        all_cves.add(cve_id)

            # if no cve why search severity
            if all_cves:
                severity_service = CVESeverityService()
                severity_map = asyncio.run(
                    severity_service.get_multiple_severities(all_cves)
                )

                max_severity = max(
                    severity_map.values(), 
                    key=severity_rank, 
                    default=""
                )

            # 4. Return the Vulnerability object
            return Vulnerability(
                cve_id=sorted(all_cves),
                severity=max_severity,
                vendor="MariaDB",
                product=context.get("sw_display_name", "MariaDB"),
                product_base_version=context.get("base_version"),
                product_fix_version=fix_version,
                source_id=[fix_version],
                published_date=release_date
            )

        except Exception as e:
            print(e)
            return
