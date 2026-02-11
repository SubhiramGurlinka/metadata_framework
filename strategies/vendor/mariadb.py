from strategies.base import VendorStrategy
from utils.get_json import get_json

class MariaDbVendorStrategy(VendorStrategy):
    def get_release_date(self, date_url, fix_version):
        response = get_json(date_url)
        return response['releases'][fix_version]["date_of_release"]

    def get_urls(self, product: str, base_version: str) -> list:
        # We can now use the factory to get the URL
        from factory import StrategyFactory
        return [StrategyFactory.get_url("mariadb", product, base_version)]
    
    def get_date_url(self, product: str, base_version: str) -> str:
        from factory import StrategyFactory
        return StrategyFactory.get_date_url("mariadb", product, base_version)
    
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_urls(product, base_version)[0]
        date_url = self.get_date_url(product, base_version)
        release_date = self.get_release_date(date_url, fix_version)

        context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url,
            "release_date": release_date
        }
        return self.parser.parse(url, context)