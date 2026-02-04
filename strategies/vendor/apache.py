from typing import List
from datetime import datetime
import sys
sys.path.append('/home/claude/vuln_framework')

from strategies.base import VendorStrategy, PageStrategy
from strategies.pages.apache_tomcat import ApacheTomcatPageStrategy
from infrastructure import HttpClient, SeverityCalculator
from models import Vulnerability


class ApacheVendorStrategy(VendorStrategy):
    """Vendor strategy for Apache products"""
    
    def __init__(self):
        self.http = HttpClient()
        self.severity_calc = SeverityCalculator()
        
        # Product-specific configurations
        self.product_configs = {
            "tomcat": {
                "strategy_class": ApacheTomcatPageStrategy,
                "product_name": "Apache Tomcat"
            }
        }
    
    def get_page_strategy(self, product: str) -> PageStrategy:
        """
        Get the appropriate page strategy for an Apache product
        
        Args:
            product: Product identifier (e.g., "tomcat")
            
        Returns:
            PageStrategy instance for the product
        """
        config = self.product_configs.get(product.lower())
        if not config:
            raise ValueError(f"Unsupported Apache product: {product}")
        
        strategy_class = config["strategy_class"]
        return strategy_class(self.http, self.severity_calc)
    
    def process(self, product: str, version: str, url: str) -> List[Vulnerability]:
        """
        Process an Apache product page and return vulnerabilities
        
        Args:
            product: Product identifier
            version: Product version
            url: URL to process
            
        Returns:
            List of Vulnerability objects
        """
        config = self.product_configs.get(product.lower())
        if not config:
            raise ValueError(f"Unsupported Apache product: {product}")
        
        # Get the appropriate page strategy
        page_strategy = self.get_page_strategy(product)
        
        # Parse the page
        result = page_strategy.parse(url, version)
        
        # Check for errors
        if "error" in result:
            print(f"Warning: {result['error']}")
            return []
        
        # Convert to Vulnerability objects
        vulnerabilities = []
        release_date = self._parse_date(result.get("release_date"))
        
        for cve_data in result.get("cves", []):
            vuln = Vulnerability(
                cve_id=[cve_data["cve"]],
                severity=cve_data["severity"],
                published_date=release_date,
                vendor="Apache",
                product=result["product"],
                source_id=result.get("source_id"),
                cvss=cve_data.get("cvss")
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime object"""
        if not date_str:
            return None
        
        # Try common date formats
        formats = [
            "%d %B %Y",       # 15 January 2024
            "%B %d, %Y",      # January 15, 2024
            "%Y-%m-%d",       # 2024-01-15
            "%m/%d/%Y",       # 01/15/2024
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        return None