import re
from typing import Dict, Optional
from bs4 import BeautifulSoup
import sys
sys.path.append('/home/claude/vuln_framework')

from strategies.base import PageStrategy
from infrastructure import HttpClient, SeverityCalculator


class ApacheTomcatPageStrategy(PageStrategy):
    """Strategy for parsing Apache Tomcat security pages"""
    
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    
    def __init__(self, http: HttpClient, severity_calc: SeverityCalculator):
        self.http = http
        self.severity_calc = severity_calc
    
    def parse(self, url: str, version: str, **kwargs) -> Dict:
        """
        Parse Apache Tomcat security page
        
        Args:
            url: The URL to parse
            version: The version to extract (e.g., "9.0.109")
        """
        soup = self.http.get_soup(url)
        
        # Build header ID (e.g., "Fixed_in_Apache_Tomcat_9.0.109")
        header_id = f"Fixed_in_Apache_Tomcat_{version}"
        header = soup.find("h3", {"id": header_id})
        
        if not header:
            return {
                "error": "Version block not found",
                "product": "Apache Tomcat",
                "version": version
            }
        
        # Extract release date from span
        release_date = self._extract_release_date(header)
        
        # Parse CVEs from following div
        cves = self._parse_cves(header)
        
        return {
            "product": "Apache Tomcat",
            "version": version,
            "release_date": release_date,
            "cves": cves,
            "source_id": version
        }
    
    def _extract_release_date(self, header) -> Optional[str]:
        """Extract release date from span element"""
        date_span = header.find("span", class_="pull-right")
        return date_span.get_text(strip=True) if date_span else None
    
    def _parse_cves(self, header) -> list:
        """Parse CVE entries from paragraph elements"""
        output = []
        
        next_node = header.find_next_sibling()
        while next_node and next_node.name == "div":
            for p in next_node.find_all("p"):
                text = p.get_text(strip=True)
                
                # Find CVE IDs
                cves = self.CVE_REGEX.findall(text)
                if not cves:
                    continue
                
                # Extract severity (e.g., "Low:", "Important:", "Critical:")
                severity_match = re.match(r"^(Low|Medium|Important|Critical):", text)
                severity = severity_match.group(1) if severity_match else "Unknown"
                
                # Normalize severity
                severity = self.severity_calc.normalize(severity)
                
                for cve in cves:
                    output.append({
                        "cve": cve,
                        "severity": severity,
                        "cvss": None  # Tomcat doesn't provide CVSS in the same format
                    })
            break
        
        return output