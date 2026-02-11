from abc import ABC, abstractmethod
from typing import List
from models import Vulnerability

class PageParser(ABC):
    """Abstract class for specific page structures (e.g., HTML Tables, JSON APIs)."""
    
    @abstractmethod
    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        """
        Parses raw content into a list of Vulnerability objects.
        'context' carries metadata like product name and version.
        """
        pass

class VendorStrategy(ABC):
    """Abstract class for Vendor routing (IBM, RedHat, etc.)."""

    def __init__(self, parser: PageParser, software_cfg: dict, vendor_cfg: dict):
        self.parser = parser
        self.software_cfg = software_cfg
        self.vendor_cfg = vendor_cfg

    def get_config(self, key: str, default=None):
        """
        Implements shadowing: Software-level values override Vendor-level values.
        """
        # 1. Try to get the specific software override
        if key in self.software_cfg:
            return self.software_cfg[key]
        
        # 2. Fall back to the general vendor default
        if key in self.vendor_cfg:
            return self.vendor_cfg[key]
        
        # 3. Return the hardcoded default if neither exists
        return default
    
    def get_registry_value_from_software_cfg(self, key: str, default=None):
        """Dynamic lookup for any field in the registry for this product."""
        return self.software_cfg.get(key, default)

    def get_registry_value_from_vendor_cfg(self, key: str, default=None):
        """Dynamic lookup for any field in the registry for this vendor."""
        return self.vendor_cfg.get(key, default)

    @abstractmethod
    def get_urls(self, product: str, base_version: str) -> List[str]:
        """Determines the correct URLs to scrape based on registry/logic."""
        pass

    @abstractmethod
    def process(self, product: str, base_version: str) -> List[Vulnerability]:
        """The main orchestration logic for a specific vendor."""
        pass