# mariadb.py

import re
from strategies.base import VendorStrategy
from utils.get_text import get_response_text
from utils.format_date import format_date

class MariaDbVendorStrategy(VendorStrategy):

    def get_release_date(self, date_url):
        r = get_response_text(date_url)

        for line in r.splitlines():
            if "Release date" in line.strip():
                match = re.search(r"Release date.*?(\d{1,2}\s+\w+\s+\d{4})", line)
                if match:
                    return format_date(match.group(1))
        return
    
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        date_url = self.software_cfg.get("base_date_url") + f"{base_version}/{fix_version}.md"
        release_date = self.get_release_date(date_url)
        
        context = {
            "url": url,
            "product": product,
            "base_version": base_version,
            "release_date": release_date,
            "product_fix_version": fix_version,
            "sw_display_name": self.software_cfg.get("display_name")
        }
        return self.parser.parse(url, context)