# oracle.py

from datetime import datetime
from utils.get_soup import get_soup
from strategies.base import VendorStrategy


class OracleVendorStrategy(VendorStrategy):

    def format_date(self, date: str) -> str:
        dt = datetime.strptime(date.strip(), "%Y-%B-%d")
        return dt.strftime("%Y-%m-%d")

    def latest_cpu_url(self, base_url) -> tuple[str, str]:
        soup = get_soup(base_url, "html.parser")
        if isinstance(soup, Exception):
            raise RuntimeError("Failed to fetch base page")

        table = soup.find("table")
        if not table:
            raise ValueError("CPU table not found")

        link = table.find("a", href=True)
        if not link:
            raise ValueError("CPU link not found")

        href = link.get("href")        
        source_id = href.rsplit('/', 1)[1].rsplit('.', 1)[0]
        return base_url + '/' + source_id + '.html', source_id

    def get_release_date(self, cpu_url: str) -> str:
        soup = get_soup(cpu_url, "html.parser")
        if isinstance(soup, Exception):
            raise RuntimeError("Failed to fetch CPU page")

        mod_h3 = soup.find(
            "h3",
            string=lambda text: text and text.lower() == "modification history"
        )

        if not mod_h3:
            raise ValueError("Modification history section not found")

        table = mod_h3.find_next("table")
        if not table:
            raise ValueError("Modification history table not found")

        tbodies = table.find_all("tbody")
        if not tbodies:
            raise ValueError("No table body found")

        rows = tbodies[-1].find_all("tr")
        if not rows:
            raise ValueError("No rows found in modification table")

        last_row = rows[-1]
        release_date = last_row.find("td").text
        return self.format_date(release_date)

    def process(self, product: str, base_version: str, fix_version: str):
        base_url = self.get_url(base_version)
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