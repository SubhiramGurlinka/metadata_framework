import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List
import asyncio

from strategies.base import PageParser
from models import Vulnerability
from utils.get_text import get_response_text
from utils.get_severity import CVESeverityService
from strategies.parsers.utils.general_utilities import normalize_date_to_iso

class IBMDB2FixListParser(PageParser):

    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    DEFAULT_SEVERITY = ""
    SEVERITY_RANK = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "None": 0,
        "Unknown": 0
    }

    @staticmethod
    def split_db2_version(version: str) -> tuple[str, str]:
        parts = version.split(".")

        if len(parts) < 3:
            raise ValueError("Version must be major.minor.fix")

        base_version = ".".join(parts[:2])
        fix_version = parts[2]

        return base_version, fix_version
    
    def get_highest_severity(self, severity_map: dict) -> str:

        highest = "Unknown"
        highest_rank = -1

        for severity in severity_map.values():
            rank = self.SEVERITY_RANK.get(severity, 0)

            if rank > highest_rank:
                highest_rank = rank
                highest = severity

        return highest

    def get_source_id_and_release_date(self, url: str, base_version: str, fix_version: str):

        response_text = get_response_text(url)

        soup = BeautifulSoup(response_text, "html.parser")

        target_version = f"Db2 {base_version}"

        _, minor_version = self.split_db2_version(fix_version)

        table = soup.find("table", summary=lambda x: x and target_version in x)

        if not table:
            return None, None, None

        fixpack_pattern = re.compile(rf"^Mod\s+{minor_version}\s+Fix\s+Pack\s+0$")
        document_pattern = re.compile(r"/(\d+)$")

        fixpack_link = None
        source_id = None

        for row in table.find_all("tr"):
            text = row.get_text(strip=True)

            if fixpack_pattern.match(text):

                link_tag = row.find("a")

                if link_tag:
                    fixpack_link = urljoin(url, link_tag["href"])

                    doc_match = document_pattern.search(link_tag["href"])
                    if doc_match:
                        source_id = doc_match.group(1)

                break

        if not fixpack_link:
            return None, None, None

        response_text = get_response_text(fixpack_link)

        soup = BeautifulSoup(response_text, "html.parser")

        release_date_table = soup.find(
            "table",
            summary=lambda x: x and "Fix Pack INFO" in x
        )

        release_date = None

        if release_date_table:

            escaped_fix_version = re.escape(fix_version)

            release_pattern = re.compile(
                rf"Signature:({escaped_fix_version}\.\d+).*?"
                rf"Release\s*Date:\s*([0-9]{{1,2}}\.[A-Za-z]+\.[0-9]{{4}})"
            )

            for row in release_date_table.find_all("tr"):
                row_text = row.get_text(strip=True)

                match = release_pattern.search(row_text)

                if match:
                    release_date = match.group(2)
                    break

        apar_fixlist_pattern = re.compile(
            fr"Db2\s*{re.escape(base_version)}\s*APAR\s*Fix\s*List",
            re.I
        )

        anchor = soup.find("a", string=apar_fixlist_pattern)

        cve_page_href = anchor.get("href") if anchor else None

        return source_id, release_date, cve_page_href

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        # here the content is not used and becomes obsolete for this usecase, but we keep it for compatibility with the interface
        fix_version = context.get("product_fix_version")
        base_version = context.get("base_version")
        date_url = context.get("date_url")

        if not (fix_version and base_version and date_url):
            return []

        # Step 1 — Get metadata and APAR page
        source_id, release_date, cve_page_href = self.get_source_id_and_release_date(
            date_url,
            base_version,
            fix_version
        )

        if not cve_page_href:
            return []

        # Step 2 — Fetch CVE/APAR page
        response_text = get_response_text(cve_page_href)

        soup = BeautifulSoup(response_text, "html.parser")

        matched_table = None

        # 1. Iterate over all DB2 fix tables
        for table in soup.find_all("table", class_="bx--data-table"):
            thead = table.find("thead")
            if not thead:
                continue

            header_text = thead.get_text(" ", strip=True)

            # Example header: "Db2 12.1.2 Fix Pack m2fp0"
            if fix_version in header_text:
                matched_table = table
                break

        if not matched_table:
            return []

        # 3. Extract CVEs from tbody
        all_cves = set()
        tbody = matched_table.find("tbody")
        if not tbody:
            return []

        for row in tbody.find_all("tr"):
            text = row.get_text(" ", strip=True)
            all_cves.update(self.CVE_REGEX.findall(text))

        print("The CVEs are ", len(all_cves))

        severity_service = CVESeverityService()
        severity_map = asyncio.run(
        severity_service.get_multiple_severities(all_cves)
        )
        highest_severity = max(
        severity_map.values(),
        key=lambda s: self.SEVERITY_RANK.get(s, 0),
        default=""
        )

        if highest_severity in ("None", "Unknown"):
            highest_severity = ""

        # Step 4 — Build object
        vulnerability = Vulnerability(
            cve_id=sorted(all_cves),
            severity=highest_severity,
            vendor="IBM",
            product=context.get("product", "IBM Db2"),
            product_base_version=base_version,
            product_fix_version=fix_version,
            source_id=[source_id],
            published_date=normalize_date_to_iso(release_date) if release_date else None
        )

        return vulnerability