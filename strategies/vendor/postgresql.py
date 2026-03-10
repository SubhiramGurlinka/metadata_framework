# postgresql.py

from strategies.base import VendorStrategy
from utils.get_text import get_response_text

class PostgreSqlVendorStrategy(VendorStrategy):
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        date_url = self.software_cfg.get("base_date_url") + fix_version
        
        context = {
            "url": url,
            "product": product,
            "base_version": base_version,
            "date_url": date_url,
            "product_fix_version": fix_version,
            "sw_display_name": self.software_cfg.get("display_name")
        }
        return self.parser.parse(get_response_text(url), context)