# # registry.py
# from strategies.ibm_fixpack_strategy import IBMFixpackStrategy
# from strategies.tomcat_page_strategy import TomcatPageStrategy

# REGISTRY = {
#     "websphere": IBMFixpackStrategy,
#     "mq": IBMFixpackStrategy,
#     "db2": IBMFixpackStrategy,

#     "tomcat": TomcatPageStrategy,
# }

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ProductMetadata:
    """Metadata about a product"""
    vendor: str
    product: str
    page_type: str
    url_template: Optional[str] = None
    supported_versions: Optional[List[str]] = None
    
    def get_url(self, version: str = None) -> str:
        """Get the URL for a specific version or the default URL"""
        if self.url_template and version:
            return self.url_template.format(version=version)
        return self.url_template


class ProductRegistry:
    """Registry storing metadata about products and their vendors"""
    
    def __init__(self):
        self._registry: Dict[str, ProductMetadata] = {}
        self._initialize_products()
    
    def _initialize_products(self):
        """Initialize the registry with known products"""
        
        # IBM Products
        self.register(
            key="ibm-mq",
            metadata=ProductMetadata(
                vendor="ibm",
                product="ibm-mq",
                page_type="fixpack",
                url_template="https://www.ibm.com/support/pages/fix-list-ibm-mq-version-9.1-lts",
                supported_versions=["9.1", "9.2", "9.3"]
            )
        )
        
        self.register(
            key="websphere",
            metadata=ProductMetadata(
                vendor="ibm",
                product="websphere",
                page_type="fixpack",
                url_template="https://www.ibm.com/support/pages/fix-list-ibm-websphere-application-server-v{version}",
                supported_versions=["8.5", "9.0"]
            )
        )
        
        self.register(
            key="db2",
            metadata=ProductMetadata(
                vendor="ibm",
                product="db2",
                page_type="fixpack",
                url_template="https://www.ibm.com/support/pages/fix-list-db2-version-{version}-linux-unix-and-windows",
                supported_versions=["11.5", "12.1"]
            )
        )
        
        # Apache Products
        self.register(
            key="tomcat-9",
            metadata=ProductMetadata(
                vendor="apache",
                product="tomcat",
                page_type="security",
                url_template="https://tomcat.apache.org/security-9.html",
                supported_versions=None  # All 9.x versions
            )
        )
        
        self.register(
            key="tomcat-10",
            metadata=ProductMetadata(
                vendor="apache",
                product="tomcat",
                page_type="security",
                url_template="https://tomcat.apache.org/security-10.html",
                supported_versions=None  # All 10.x versions
            )
        )
    
    def register(self, key: str, metadata: ProductMetadata):
        """
        Register a product
        
        Args:
            key: Unique identifier for the product
            metadata: Product metadata
        """
        self._registry[key] = metadata
    
    def get(self, key: str) -> Optional[ProductMetadata]:
        """
        Get product metadata by key
        
        Args:
            key: Product identifier
            
        Returns:
            ProductMetadata if found, None otherwise
        """
        return self._registry.get(key)
    
    def list_products(self) -> List[str]:
        """List all registered product keys"""
        return list(self._registry.keys())
    
    def list_by_vendor(self, vendor: str) -> List[str]:
        """
        List all products for a specific vendor
        
        Args:
            vendor: Vendor name
            
        Returns:
            List of product keys for the vendor
        """
        return [
            key for key, metadata in self._registry.items()
            if metadata.vendor.lower() == vendor.lower()
        ]