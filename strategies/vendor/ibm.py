from strategies.base import VendorStrategy
import requests

class IBMVendorStrategy(VendorStrategy):
    def get_urls(self, product: str, base_version: str) -> list:
        # We can now use the factory to get the URL
        from factory import StrategyFactory
        return [StrategyFactory.get_url("ibm", product, base_version)]

    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_urls(product, base_version)[0]
        response = requests.get(url, timeout=15)
        
        context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url
        }
        return self.parser.parse(response.text, context)