# from strategies.pages.ibm_fixpack import IBMFixpackPageStrategy
# from http_client import HttpClient
# from registry import REGISTRY

# class IBMVendorStrategy:

#     def get_page_strategy(self, product: str, version: str, url: str):
#         config = REGISTRY[product]

#         return IBMFixpackPageStrategy(
#             http_client=HttpClient(),
#             url=url,
#             version=version,
#             product=product,
#             header_regex=config["header_regex"],
#             date_regex=config["date_regex"],
#             cvss_regex=config["cvss_regex"],
#         )
from typing import List
from datetime import datetime
import sys
sys.path.append('/home/claude/vuln_framework')

from strategies.base import VendorStrategy, PageStrategy
from strategies.pages.ibm_fixpack import IbmFixPackPageStrategy, IbmDb2PageStrategy
from infrastructure import HttpClient, CveTableParser, SeverityCalculator
from models import Vulnerability


class IbmVendorStrategy(VendorStrategy):
    """Vendor strategy for IBM products"""
    
    def __init__(self):
        self.http = HttpClient()
        self.severity_calc = SeverityCalculator()
        
        # Product-specific configurations
        self.product_configs = {
            "ibm-mq": {
                "strategy_class": IbmFixPackPageStrategy,
                "parser_cvss_regex": r"CVSS base score (\d+\.\d+)",
                "header_pattern": "IBM MQ cumulative security update {version}",
                "date_pattern": r"Last modified:",
                "product_name": "IBM MQ"
            },
            "websphere": {
                "strategy_class": IbmFixPackPageStrategy,
                "parser_cvss_regex": r"CVSS (\d+\.\d+)",
                "header_pattern": "Fix Pack {version}",
                "date_pattern": r"Fix release date:",
                "product_name": "IBM WebSphere Application Server"
            },
            "db2": {
                "strategy_class": IbmDb2PageStrategy,
                "parser_cvss_regex": r"CVSS (\d+\.\d+)",
                "product_name": "IBM DB2"
            }
        }
    
    def get_page_strategy(self, product: str) -> PageStrategy:
        """
        Get the appropriate page strategy for an IBM product
        
        Args:
            product: Product identifier (e.g., "ibm-mq", "websphere", "db2")
            
        Returns:
            PageStrategy instance for the product
        """
        config = self.product_configs.get(product.lower())
        if not config:
            raise ValueError(f"Unsupported IBM product: {product}")
        
        # Create parser with product-specific CVSS regex
        parser = CveTableParser(
            self.severity_calc,
            cvss_regex=config["parser_cvss_regex"]
        )
        
        # Create and return the appropriate strategy
        strategy_class = config["strategy_class"]
        return strategy_class(self.http, parser)
    
    def process(self, product: str, version: str, url: str) -> List[Vulnerability]:
        """
        Process an IBM product page and return vulnerabilities
        
        Args:
            product: Product identifier
            version: Product version
            url: URL to process
            
        Returns:
            List of Vulnerability objects
        """
        config = self.product_configs.get(product.lower())
        if not config:
            raise ValueError(f"Unsupported IBM product: {product}")
        
        # Get the appropriate page strategy
        page_strategy = self.get_page_strategy(product)
        
        # Parse the page
        kwargs = {
            "product_name": config["product_name"]
        }
        if "header_pattern" in config:
            kwargs["header_pattern"] = config["header_pattern"]
        if "date_pattern" in config:
            kwargs["date_pattern"] = config["date_pattern"]
        
        result = page_strategy.parse(url, version, **kwargs)
        
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
                vendor="IBM",
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
            "%B %d, %Y",      # January 15, 2024
            "%d %B %Y",       # 15 January 2024
            "%Y-%m-%d",       # 2024-01-15
            "%m/%d/%Y",       # 01/15/2024
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        return None