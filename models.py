from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class Vulnerability:
    """Domain model for a vulnerability entry"""
    cve_id: List[str]
    severity: str
    published_date: Optional[datetime]
    vendor: str
    product: str
    source_id: Optional[str] = None
    cvss: Optional[float] = None
    
    def __post_init__(self):
        """Validate the model after initialization"""
        if not self.cve_id:
            raise ValueError("At least one CVE ID is required")
        if not self.vendor:
            raise ValueError("Vendor is required")
        if not self.product:
            raise ValueError("Product is required")