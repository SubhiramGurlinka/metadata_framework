# ibm.py

from strategies.base import VendorStrategy
import requests

class IBMVendorStrategy(VendorStrategy):
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        response = requests.get(url, timeout=15)
        if self.software_cfg.get("base_date_url"):
            context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url,
            "date_url": self.software_cfg.get("base_date_url")
            }
        else:
            context = {
                "product": product,
                "base_version": base_version,
                "product_fix_version": fix_version,
                "url": url
            }
        return self.parser.parse(response.text, context)