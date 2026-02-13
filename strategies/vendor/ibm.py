from strategies.base import VendorStrategy
import requests

class IBMVendorStrategy(VendorStrategy):
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        response = requests.get(url, timeout=15)
        
        context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url
        }
        return self.parser.parse(response.text, context)