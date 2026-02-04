# from abc import ABC, abstractmethod
# from typing import List
# from models import Vulnerability

# class PageStrategy(ABC):

#     @abstractmethod
#     def run(self) -> List[Vulnerability]:
#         pass


# class VendorStrategy(ABC):

#     @abstractmethod
#     def get_page_strategy(self, product: str, **kwargs) -> PageStrategy:
#         pass

#     def process(self, product: str, **kwargs) -> List[Vulnerability]:
#         page = self.get_page_strategy(product, **kwargs)
#         return page.run()
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from models import Vulnerability


class PageStrategy(ABC):
    """Abstract base class for parsing specific page types"""
    
    @abstractmethod
    def parse(self, url: str, version: str, **kwargs) -> Dict[str, Any]:
        """
        Parse a page and extract vulnerability information
        
        Args:
            url: The URL to parse
            version: The product version to extract
            **kwargs: Additional parameters specific to the page type
            
        Returns:
            Dictionary containing parsed data including CVEs, dates, etc.
        """
        pass


class VendorStrategy(ABC):
    """Abstract base class for vendor-specific processing"""
    
    @abstractmethod
    def process(self, product: str, version: str, url: str) -> List[Vulnerability]:
        """
        Process a product page and return a list of vulnerabilities
        
        Args:
            product: The product name
            version: The product version
            url: The URL to process
            
        Returns:
            List of Vulnerability objects
        """
        pass
    
    @abstractmethod
    def get_page_strategy(self, product: str) -> PageStrategy:
        """
        Get the appropriate page strategy for a given product
        
        Args:
            product: The product name
            
        Returns:
            PageStrategy instance for parsing the product's page
        """
        pass