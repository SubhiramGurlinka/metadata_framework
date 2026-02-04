# import re
# from bs4 import BeautifulSoup
# from typing import List
# from strategies.base import PageStrategy
# from models import Vulnerability


# class IBMFixpackPageStrategy(PageStrategy):

#     def __init__(
#         self,
#         http_client,
#         url: str,
#         version: str,
#         product: str,
#         header_regex: str,
#         date_regex: str,
#         cvss_regex: str,
#     ):
#         self.http = http_client
#         self.url = url
#         self.version = version
#         self.product = product
#         self.header_regex = header_regex
#         self.date_regex = date_regex
#         self.cvss_regex = re.compile(cvss_regex)
#         self.cve_regex = re.compile(r"CVE-\d{4}-\d+")

#     def run(self) -> List[Vulnerability]:
#         soup = self.http.get_soup(self.url)

#         header = self._find_header(soup)
#         release_date = self._extract_date(header)
#         table = header.find_next("table")

#         vulns = []
#         seen = set()

#         for row in table.find_all("tr"):
#             text = row.get_text(" ", strip=True)

#             cves = self.cve_regex.findall(text)
#             if not cves:
#                 continue

#             cvss_match = self.cvss_regex.search(text)
#             cvss = float(cvss_match.group(1)) if cvss_match else None
#             severity = self._severity_from_cvss(cvss)

#             for cve in cves:
#                 if cve in seen:
#                     continue
#                 seen.add(cve)

#                 vulns.append(
#                     Vulnerability(
#                         cve_id=cve,
#                         severity=severity,
#                         published_date=release_date,
#                         vendor="IBM",
#                         product=self.product,
#                         source_id=self.version,
#                     )
#                 )

#         return vulns

#     def _find_header(self, soup: BeautifulSoup):
#         pattern = re.compile(
#             self.header_regex.format(version=re.escape(self.version)),
#             re.I,
#         )
#         for h3 in soup.find_all("h3"):
#             if pattern.search(h3.get_text(strip=True)):
#                 return h3
#         raise ValueError("Version block not found")

#     def _extract_date(self, header):
#         node = header.find_next(string=re.compile(self.date_regex, re.I))
#         return node.strip() if node else None

#     @staticmethod
#     def _severity_from_cvss(cvss):
#         if cvss is None:
#             return "Unknown"
#         if cvss < 4.0:
#             return "Low"
#         if cvss < 7.0:
#             return "Medium"
#         if cvss < 9.0:
#             return "High"
#         return "Critical"

import re
from typing import Dict, Optional
from bs4 import BeautifulSoup
import sys
sys.path.append('/home/claude/vuln_framework')

from strategies.base import PageStrategy
from infrastructure import HttpClient, CveTableParser, SeverityCalculator


class IbmFixPackPageStrategy(PageStrategy):
    """Strategy for parsing IBM Fix Pack pages (MQ, WebSphere, DB2)"""
    
    def __init__(self, http: HttpClient, parser: CveTableParser):
        self.http = http
        self.parser = parser
    
    def parse(self, url: str, version: str, **kwargs) -> Dict:
        """
        Parse IBM Fix Pack page
        
        Args:
            url: The URL to parse
            version: The version to extract
            **kwargs: Must contain 'product_name' and 'header_pattern'
        """
        product_name = kwargs.get('product_name', 'IBM Product')
        header_pattern = kwargs.get('header_pattern')
        date_pattern = kwargs.get('date_pattern', r"Last modified:|Fix release date:")
        
        soup = self.http.get_soup(url)
        
        # Find the version header
        header = self._find_version_header(soup, version, header_pattern)
        if not header:
            return {
                "error": f"Version {version} not found",
                "product": product_name,
                "version": version
            }
        
        # Extract release date
        release_date = self._extract_release_date(header, date_pattern)
        
        # Find and parse the CVE table
        table = header.find_next("table")
        if not table:
            return {
                "error": "No CVE table found",
                "product": product_name,
                "version": version,
                "release_date": release_date
            }
        
        cves = self.parser.parse(table)
        
        return {
            "product": product_name,
            "version": version,
            "release_date": release_date,
            "cves": cves,
            "source_id": version
        }
    
    def _find_version_header(self, soup: BeautifulSoup, version: str, pattern: str):
        """Find the header element for the specified version"""
        regex = re.compile(pattern.format(version=re.escape(version)), re.I)
        
        # Try h3 first
        for tag in soup.find_all(["h3", "h2"]):
            if regex.search(tag.get_text(strip=True)):
                return tag
        
        # Try string search
        anchor = soup.find(string=regex)
        if anchor:
            return anchor
        
        return None
    
    def _extract_release_date(self, header, date_pattern: str) -> Optional[str]:
        """Extract release date from the section"""
        date_regex = re.compile(date_pattern, re.I)
        
        # Check next h3 elements
        next_h3 = header.find_next("h3")
        while next_h3:
            text = next_h3.get_text(strip=True)
            if date_regex.search(text):
                return text.split(":", 1)[-1].strip(" ()")
            next_h3 = next_h3.find_next("h3")
        
        # Alternative: search for date string after header
        date_node = header.find_next(string=date_regex)
        if date_node:
            return date_node.strip()
        
        return None


class IbmDb2PageStrategy(PageStrategy):
    """Strategy for parsing IBM DB2 Fix List pages"""
    
    def __init__(self, http: HttpClient, parser: CveTableParser):
        self.http = http
        self.parser = parser
    
    def parse(self, url: str, version: str, **kwargs) -> Dict:
        """
        Parse DB2 Fix List page
        
        Args:
            url: The URL to parse
            version: The version to extract
        """
        soup = self.http.get_soup(url)
        
        # Find table containing the version
        table = self._find_target_table(soup, version)
        if not table:
            return {
                "error": "DB2 Fix table not found",
                "product": "IBM DB2",
                "version": version
            }
        
        cves = self.parser.parse(table)
        
        return {
            "product": "IBM DB2",
            "version": version,
            "cves": cves,
            "source_id": version
        }
    
    def _find_target_table(self, soup: BeautifulSoup, version: str):
        """Find the table containing the specified version"""
        pattern = re.compile(rf"Db2 {re.escape(version)} Fix Pack", re.I)
        
        for table in soup.find_all("table"):
            if pattern.search(table.get_text(" ", strip=True)):
                return table
        
        return None