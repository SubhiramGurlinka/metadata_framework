import re
import requests
from bs4 import BeautifulSoup
from typing import Optional, List, Dict


class HttpClient:
    """HTTP client for fetching web pages"""
    
    def get_soup(self, url: str, timeout: int = 15) -> BeautifulSoup:
        """
        Fetch a URL and return a BeautifulSoup object
        
        Args:
            url: The URL to fetch
            timeout: Request timeout in seconds
            
        Returns:
            BeautifulSoup object for parsing
        """
        res = requests.get(url, timeout=timeout)
        res.raise_for_status()
        return BeautifulSoup(res.text, "html.parser")


class SeverityCalculator:
    """Calculate severity levels from CVSS scores"""
    
    @staticmethod
    def from_cvss(cvss: Optional[float]) -> str:
        """
        Convert CVSS score to severity level
        
        Args:
            cvss: CVSS base score (0-10)
            
        Returns:
            Severity level: Low, Medium, High, Critical, or Unknown
        """
        if cvss is None:
            return "Unknown"
        if cvss < 4.0:
            return "Low"
        if cvss < 7.0:
            return "Medium"
        if cvss < 9.0:
            return "High"
        return "Critical"
    
    @staticmethod
    def normalize(severity: str) -> str:
        """
        Normalize severity strings to standard values
        
        Args:
            severity: Input severity string
            
        Returns:
            Normalized severity: Low, Medium, High, Critical, or Unknown
        """
        severity_map = {
            "important": "High",
            "moderate": "Medium",
            "low": "Low",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium"
        }
        return severity_map.get(severity.lower(), severity)


class CveTableParser:
    """Generic CVE table parser with configurable regex patterns"""
    
    CVE_REGEX = re.compile(r"CVE-\d{4}-\d+")
    
    def __init__(self, severity_calculator: SeverityCalculator, cvss_regex: str = r"CVSS (\d+\.\d+)"):
        """
        Initialize the parser
        
        Args:
            severity_calculator: SeverityCalculator instance
            cvss_regex: Regular expression pattern for extracting CVSS scores
        """
        self.severity_calculator = severity_calculator
        self.cvss_regex = re.compile(cvss_regex)
    
    def parse(self, table) -> List[Dict]:
        """
        Parse a table and extract CVE information
        
        Args:
            table: BeautifulSoup table element
            
        Returns:
            List of dictionaries containing CVE data
        """
        results = []
        seen = set()
        
        for row in table.find_all("tr"):
            text = row.get_text(" ", strip=True)
            
            cves = self.CVE_REGEX.findall(text)
            if not cves:
                continue
            
            cvss_match = self.cvss_regex.search(text)
            cvss = float(cvss_match.group(1)) if cvss_match else None
            severity = self.severity_calculator.from_cvss(cvss)
            
            for cve in cves:
                if cve in seen:
                    continue
                seen.add(cve)
                
                results.append({
                    "cve": cve,
                    "cvss": cvss,
                    "severity": severity
                })
        
        return results