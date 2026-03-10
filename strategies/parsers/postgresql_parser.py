import re
from bs4 import BeautifulSoup
from typing import List, Dict
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso
from utils.cvss_to_severity import cvss_to_severity
from utils.get_text import get_response_text

class PostgreSqlParser(PageParser):
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    CVSS_REGEX = re.compile(r"(\d+\.\d+)")

    def _get_release_date(self, date_url):
        html_content = get_response_text(date_url)
        if not html_content:
            return None
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Find the paragraph that contains "Release date:"
        # We use a lambda to find a <p> that has the text regardless of inner <strong> tags
        target_p = soup.find(lambda tag: tag.name == "p" and "Release date:" in tag.get_text())

        if target_p:
            p_text = target_p.get_text(strip=True)
            print(f"Found paragraph text: {p_text}")
            
            match = re.search(r'Release date:\s*(\d{4}-\d{2}-\d{2})', p_text)
            if match:
                return match.group(1)
        
        global_match = re.search(r'Release date:[\s\xa0]*(\d{4}-\d{2}-\d{2})', html_content)
        if global_match:
            return global_match.group(1)

        return None

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        print("Parsing content for PostgreSQL...")
        soup = BeautifulSoup(content, 'html.parser')
        fix_version = context.get("product_fix_version")

        target = "Known PostgreSQL Security Vulnerabilities in Supported Versions".lower()

        def normalize(text: str) -> str:
            return " ".join(text.split())

        anchor = next(
            (
                h3 for h3 in soup.find_all("h3")
                if target in normalize(h3.get_text(" ", strip=True)).lower()
            ),
            None
        )

        if not anchor:
            print("Header not found")
            return None

        # 2. Extract Release Date and Table
        release_date = self._get_release_date(context.get("date_url"))
        print("Release date found: ", release_date)

        table = anchor.find_next("table")

        if not table:
            return []

        all_cves = set()
        max_cvss = 0.0
        max_severity = "Unknown"
        cvss_scores = []

        # 3. Iterate through the table rows
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            text = row.get_text(" ", strip=True)
            if fix_version in text:

                found_cves = self.CVE_REGEX.findall(text)
                
                if found_cves:
                    all_cves.update(found_cves)
                    cvss_text = cells[3].get_text()
                    # Check for CVSS (format: "CVSS 7.5")
                    cvss_match = self.CVSS_REGEX.search(cvss_text)
                    if cvss_match:
                        current_cvss = float(cvss_match.group(1))
                        cvss_scores.append(current_cvss)
        if not all_cves:
            return []

        # 4. Return the Vulnerability object
        max_cvss = max(cvss_scores) if cvss_scores else None
        max_severity = cvss_to_severity(max_cvss, 3)
        return Vulnerability(
            cve_id=sorted(list(all_cves)),
            severity=max_severity,
            vendor="PostgreSQL",
            product=context.get("sw_display_name", "PostgreSQL"),
            product_base_version=context.get("base_version"),
            product_fix_version=fix_version,
            source_id=[fix_version],
            published_date=normalize_date_to_iso(release_date) if release_date else None
        )