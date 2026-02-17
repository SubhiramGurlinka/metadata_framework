import re
from bs4 import BeautifulSoup
from typing import List
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso

class ApacheTomcatParser(PageParser):
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    
    # Severity ranking for comparison logic
    SEVERITY_RANK = {
        "Critical": 4,
        "Important": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        soup = BeautifulSoup(content, 'html.parser')
        fix_version = context.get("product_fix_version")
        
        # 1. Header Search - Match your standalone script's ID logic
        # Tomcat IDs use underscores for dots (e.g., 9.0.109 -> 9_0_109)
        header_id = f"Fixed_in_Apache_Tomcat_{fix_version}".replace(".", "_")
        header = soup.find("h3", {"id": header_id})

        # Fallback: Search by text if ID match fails (useful for varying HTML)
        if not header:
            header_pattern = re.compile(rf"Fixed in Apache Tomcat\s+{re.escape(fix_version)}", re.I)
            header = next((h3 for h3 in soup.find_all("h3") if header_pattern.search(h3.get_text())), None)

        if not header:
            return []

        # 2. Extract Date (Matches your standalone script span search)
        date_span = header.find("span", class_="pull-right")
        release_date = date_span.get_text(strip=True) if date_span else None
        
        # Additional Fallback for date if not in span (as seen in some page versions)
        if not release_date:
            date_match = re.search(r"\d{4}-\d{2}-\d{2}", header.get_text())
            if date_match:
                release_date = date_match.group(0)

        all_cves = set()
        max_severity = "Unknown"

        # 3. Traverse siblings - Matches your 'while name == div' logic
        next_node = header.find_next_sibling()
        while next_node and next_node.name == "div":
            for p in next_node.find_all("p"):
                text = p.get_text(" ", strip=True)

                # Extract CVEs
                found_cves = self.CVE_REGEX.findall(text)
                if not found_cves:
                    continue
                
                all_cves.update(found_cves)

                # Extract Severity - use search to handle <b> tags or hidden characters
                severity_match = re.search(r"\b(Low|Medium|Important|Critical):", text, re.I)
                if severity_match:
                    current_severity = severity_match.group(1).capitalize()
                    
                    # Track max severity based on SEVERITY_RANK
                    if self.SEVERITY_RANK.get(current_severity, 0) > self.SEVERITY_RANK.get(max_severity, 0):
                        max_severity = current_severity
            
            # Tomcat sections are usually one <div> block, but we continue if there are more
            next_node = next_node.find_next_sibling()
            if next_node and next_node.name == "h3": # Safety break
                break

        if not all_cves:
            return []

        return Vulnerability(
            cve_id=sorted(list(all_cves)),
            severity=max_severity,
            vendor="Apache",
            product=context.get("product", "tomcat"),
            product_base_version=context.get("base_version"),
            product_fix_version=fix_version,
            source_id=fix_version,
            published_date=normalize_date_to_iso(release_date) if release_date else None
        )