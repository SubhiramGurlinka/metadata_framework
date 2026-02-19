# base.py

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

    def get_url(self, base_version: str) -> str:
        if base_url := self.software_cfg['base_urls'].get(base_version):
            return base_url
        return self.software_cfg['base_urls'].get("all")

    @abstractmethod
    def process(self, product: str, base_version: str) -> List[Vulnerability]:
        """The main orchestration logic for a specific vendor."""
        pass