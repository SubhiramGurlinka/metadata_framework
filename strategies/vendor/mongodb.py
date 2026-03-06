# mongodb.py

from strategies.base import VendorStrategy

class MongoDbVendorStrategy(VendorStrategy):

    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version) + base_version
        
        context = {
            "url": url,
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "sw_display_name": self.software_cfg.get("display_name")
        }
        return self.parser.parse(url, context)