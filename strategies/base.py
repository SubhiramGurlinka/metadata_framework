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

    def __init__(self, parser: PageParser):
        self.parser = parser

    @abstractmethod
    def get_urls(self, product: str, base_version: str) -> List[str]:
        """Determines the correct URLs to scrape based on registry/logic."""
        pass

    @abstractmethod
    def process(self, product: str, base_version: str) -> List[Vulnerability]:
        """The main orchestration logic for a specific vendor."""
        pass