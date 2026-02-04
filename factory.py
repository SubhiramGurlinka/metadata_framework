# from strategies.vendor.ibm import IBMVendorStrategy
# from strategies.vendor.oracle import OracleVendorStrategy
# from strategies.vendor.redhat import RedHatVendorStrategy
# from strategies.vendor.apache import ApacheVendorStrategy

# class VendorFactory:

#     @staticmethod
#     def get(vendor: str):
#         mapping = {
#             "ibm": IBMVendorStrategy,
#             "oracle": OracleVendorStrategy,
#             "redhat": RedHatVendorStrategy,
#             "apache": ApacheVendorStrategy,
#         }

#         if vendor.lower() not in mapping:
#             raise ValueError("Unsupported vendor")

#         return mapping[vendor.lower()]()


from typing import Dict
import sys
sys.path.append('/home/claude/vuln_framework')

from strategies.base import VendorStrategy
from strategies.vendor.ibm import IbmVendorStrategy
from strategies.vendor.apache import ApacheVendorStrategy


class VendorStrategyFactory:
    """Factory for creating vendor strategy instances"""
    
    def __init__(self):
        self._strategies: Dict[str, VendorStrategy] = {}
        self._strategy_classes = {
            "ibm": IbmVendorStrategy,
            "apache": ApacheVendorStrategy
        }
    
    def get_strategy(self, vendor: str) -> VendorStrategy:
        """
        Get or create a vendor strategy instance
        
        Args:
            vendor: Vendor name (e.g., "ibm", "apache")
            
        Returns:
            VendorStrategy instance
            
        Raises:
            ValueError: If vendor is not supported
        """
        vendor_key = vendor.lower()
        
        # Return cached instance if it exists
        if vendor_key in self._strategies:
            return self._strategies[vendor_key]
        
        # Create new instance
        strategy_class = self._strategy_classes.get(vendor_key)
        if not strategy_class:
            raise ValueError(f"Unsupported vendor: {vendor}")
        
        strategy = strategy_class()
        self._strategies[vendor_key] = strategy
        
        return strategy
    
    def register_strategy(self, vendor: str, strategy_class: type):
        """
        Register a new vendor strategy class
        
        Args:
            vendor: Vendor name
            strategy_class: VendorStrategy subclass
        """
        self._strategy_classes[vendor.lower()] = strategy_class
    
    def list_vendors(self) -> list:
        """List all supported vendors"""
        return list(self._strategy_classes.keys())