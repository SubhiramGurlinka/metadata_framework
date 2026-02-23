# mariadb.py

from strategies.base import VendorStrategy
from utils.get_json import get_json

class MariaDbVendorStrategy(VendorStrategy):
    def get_release_date(self, date_url, fix_version):
        response = get_json(date_url)
        return response['releases'][fix_version]["date_of_release"]
    
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        date_url = self.software_cfg.get("base_date_url") + base_version
        release_date = self.get_release_date(date_url, fix_version)
        
        context = {
            "url": url,
            "product": product,
            "base_version": base_version,
            "release_date": release_date,
            "product_fix_version": fix_version,
            "sw_display_name": self.software_cfg.get("display_name")
        }
        return self.parser.parse(url, context)