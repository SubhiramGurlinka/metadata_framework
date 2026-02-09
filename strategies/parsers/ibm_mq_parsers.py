import re
from bs4 import BeautifulSoup
from typing import List, Dict
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso

class IBMMQTableParser(PageParser):
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    CVSS_REGEX = re.compile(r"CVSS base score (\d+\.\d+)")
    HEADER_TEMPLATE = r"\bIBM MQ\b[\s\S]*?\b{version}\b"

    # Define severity ranking for comparison
    SEVERITY_RANK = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }

    def _get_release_date(self, soup, fixpack_version):
        table = soup.find('table')
        
        if not table or "release date" not in table.get_text().lower():
            return None

        # Regex for "Day Month Year" (e.g., 28 July 2025 or 01 May 2025)
        # \d{1,2} matches 1 or 2 digits for the day
        # [A-Za-z]+ matches the month name
        # \d{4} matches the 4-digit year
        date_pattern = re.compile(r'\d{1,2}\s+[A-Za-z]+\s+\d{4}')

        for row in table.find_all('tr'):
            cells = row.find_all(['td', 'th'])
            if len(cells) < 2:
                continue
                
            # Check if this row belongs to the requested fixpack
            if fixpack_version.lower() in cells[0].get_text(strip=True).lower():
                # Search all subsequent cells for a date-like string
                for cell in cells[1:]:
                    text = cell.get_text(strip=True)
                    match = date_pattern.search(text)
                    if match:
                        return match.group(0) # Returns exactly the date string found

        return None
    
    def _calculate_severity(self, cvss: float) -> str:
        if not cvss: return "Unknown"
        if cvss < 4.0: return "Low"
        if cvss < 7.0: return "Medium"
        if cvss < 9.0: return "High"
        return "Critical"

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        soup = BeautifulSoup(content, 'html.parser')
        fix_version = context.get("product_fix_version")
        release_date = self._get_release_date(soup, fix_version)
        print("the release date is: ", release_date)
        # 1. Locate the version header
        pattern = re.compile(self.HEADER_TEMPLATE.format(version=re.escape(fix_version)), re.I)
        header = next((h3 for h3 in soup.find_all("h3") if pattern.search(h3.get_text(strip=True))), None)

        if not header:
            return []

        table = header.find_next("table")
        if not table:
            return []

        # Temp storage to aggregate data
        all_cves = set()
        max_cvss = 0.0
        max_severity = "Unknown"

        # 2. Iterate and collect all unique CVEs and highest scores
        for row in table.find_all("tr"):
            text = row.get_text(" ", strip=True)
            found_cves = self.CVE_REGEX.findall(text)
            
            if found_cves:
                all_cves.update(found_cves)
                
                # Check for CVSS in the row
                cvss_match = self.CVSS_REGEX.search(text)
                if cvss_match:
                    current_cvss = float(cvss_match.group(1))
                    current_severity = self._calculate_severity(current_cvss)
                    
                    # Track max CVSS
                    if current_cvss > max_cvss:
                        max_cvss = current_cvss
                    
                    # Track max Severity based on ranking
                    if self.SEVERITY_RANK[current_severity] > self.SEVERITY_RANK[max_severity]:
                        max_severity = current_severity

        # 3. Create a single combined Vulnerability object
        if not all_cves:
            return []

        return [Vulnerability(
            cve_id=sorted(list(all_cves)), # List of strings e.g. ["CVE-...", "CVE-..."]
            severity=max_severity,
            vendor="IBM",
            product=context.get("product"),
            product_base_version=context.get("base_version"),
            product_fix_version=fix_version,
            source_id=fix_version,
            published_date=normalize_date_to_iso(release_date) if release_date else None
        )]