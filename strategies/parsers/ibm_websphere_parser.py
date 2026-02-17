import re
from bs4 import BeautifulSoup
from typing import List, Dict
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso

class IBMWebSphereTableParser(PageParser):
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    CVSS_REGEX = re.compile(r"CVSS (\d+\.\d+)")
    FIXPACK_TEMPLATE = r"Fix Pack {version}"
    DATE_REGEX = re.compile(r"Fix release date:\s*(.*)", re.I)

    # Severity ranking for comparison
    SEVERITY_RANK = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }

    def _calculate_severity(self, cvss: float) -> str:
        if cvss is None: return "Unknown"
        if cvss < 4.0: return "Low"
        if cvss < 7.0: return "Medium"
        if cvss < 9.0: return "High"
        return "Critical"

    def _extract_release_date(self, anchor) -> str:
        # WebSphere pages often have the date in a text node following the version header
        date_node = anchor.find_next(string=self.DATE_REGEX)
        if date_node:
            match = self.DATE_REGEX.search(date_node)
            return match.group(1).strip() if match else None
        return None

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        soup = BeautifulSoup(content, 'html.parser')
        fix_version = context.get("product_fix_version")
        
        # 1. Locate the Fix Pack section
        pattern = re.compile(self.FIXPACK_TEMPLATE.format(version=re.escape(fix_version)), re.I)
        anchor = soup.find(string=pattern)

        if not anchor:
            return []

        # 2. Extract Release Date and Table
        release_date = self._extract_release_date(anchor)
        table = anchor.find_next("table")
        
        if not table:
            return []

        all_cves = set()
        max_cvss = 0.0
        max_severity = "Unknown"

        # 3. Iterate through the table rows
        for row in table.find_all("tr"):
            text = row.get_text(" ", strip=True)
            found_cves = self.CVE_REGEX.findall(text)
            
            if found_cves:
                all_cves.update(found_cves)
                
                # Check for CVSS (format: "CVSS 7.5")
                cvss_match = self.CVSS_REGEX.search(text)
                if cvss_match:
                    current_cvss = float(cvss_match.group(1))
                    current_severity = self._calculate_severity(current_cvss)
                    
                    if current_cvss > max_cvss:
                        max_cvss = current_cvss
                    
                    if self.SEVERITY_RANK[current_severity] > self.SEVERITY_RANK[max_severity]:
                        max_severity = current_severity

        if not all_cves:
            return []

        # 4. Return the Vulnerability object
        return Vulnerability(
            cve_id=sorted(list(all_cves)),
            severity=max_severity,
            vendor="IBM",
            product=context.get("product", "IBM WebSphere Application Server"),
            product_base_version=context.get("base_version"),
            product_fix_version=fix_version,
            source_id=fix_version,
            published_date=normalize_date_to_iso(release_date) if release_date else None
        )