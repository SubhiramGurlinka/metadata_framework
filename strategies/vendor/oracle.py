from strategies.base import VendorStrategy
from datetime import datetime
from utils.get_soup import get_soup

class OracleVendorStrategy(VendorStrategy):
    def format_date(self, date):
        dt = datetime.strptime(date, "%Y-%B-%d")
        # Formating as yyyy-mm-dd
        return dt.strftime("%Y-%m-%d")

    def latest_cpu_url(self, base_url) -> str:
        soup = get_soup(base_url, "html.parser")
        table = soup.find("table")
        link = table.find("a", href=True)
        source_id = link["href"].rsplit('/', 1)[1].rsplit('.', 1)[0]
        return "https://www.oracle.com" + link["href"], source_id

    def get_release_date(self, cpu_url):
        try:
            cpu_soup = get_soup(cpu_url, "html.parser")
            if isinstance(cpu_soup, Exception): raise cpu_soup

            target_h3_text = "modification history"
            mod_h3 = cpu_soup.find(
                "h3",
                string=lambda text: text and text.lower() == target_h3_text
            )

            table = mod_h3.find_next("table")
            last_tbody = table.find_all("tbody")[-1]
            last_row = last_tbody.find_all("tr")[-1]

            release_date = last_row.find("td").text
            return self.format_date(release_date)
        
        except Exception as e:
            return e

    def get_urls(self, product: str, base_version: str) -> list:
        # We can now use the factory to get the URL
        from factory import StrategyFactory
        return [StrategyFactory.get_url("oracle", product, base_version)]

    def process(self, product: str, base_version: str, fix_version: str):
        base_url = self.get_urls(product, base_version)[0]
        url, source_id = self.latest_cpu_url(base_url)
        release_date = self.get_release_date(url)
        
        context = {
            "url": url,
            "product": product,
            "source_id": source_id,
            "base_version": base_version,
            "release_date": release_date,
            "product_fix_version": fix_version,
            "sw_display_name": self.software_cfg.get("display_name")
        }
        return self.parser.parse(url, context)