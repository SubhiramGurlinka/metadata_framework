from models import Vulnerability
from utils.get_soup import get_soup
from utils.cvss_to_severity import cvss_to_severity
from strategies.base import PageParser

class OracleCpuParser(PageParser):
    ORACLE_DB = False

    def row_contains_product(self, row, product):
        for td in row.find_all("td"):
            cell_text = td.get_text(strip=True).lower()
            products = [p.strip() for p in cell_text.split(",")]
            if product in products:
                return True

        return False
    
    # Cleanup is required for Java SE components (JRE/ JDK)
    def cleanup(self, product_name, cell_data):
        if ";" in cell_data:
            for item in cell_data.split(";"):
                if str(item).lower().startswith(product_name):
                    return item.split(": ")[1]
                
        return cell_data

    def parse(self, cpu_url, context):
        try:
            cpu_soup = get_soup(cpu_url, "html.parser")
            if isinstance(cpu_soup, Exception): raise cpu_soup

            product_name = context["product"].lower()
            base_version = str(context["base_version"])
            release_date = context["release_date"]

            all_cves = set()
            max_cvss = 0.0
            max_severity = "Unknown"

            # Oracle DB requires special attention
            if "oracle database" in product_name:
                self.ORACLE_DB = True
                h4_entry = f"{product_name} Risk Matrix"
                product_h4 = cpu_soup.find(
                    "h4", 
                    string=lambda s: s and s.lower() == h4_entry.lower()
                )
                products_tbody = product_h4.find_all_next("tbody")
            else:
                products_tbody = cpu_soup.find_all("tbody")[1:] # Skipping index table

            for product_tbody in products_tbody:

                # Reduced processing by enforcing only 1 table is parsed
                if max_cvss: break
                for row in product_tbody.find_all("tr"):
                    if self.row_contains_product(row, product_name) or self.ORACLE_DB:
                        cve = row.find("th").text
                        row_data = []

                        for data in row.find_all("td"):
                            row_data.append(data.text)
                        
                        affected_versions = self.cleanup(product_name, row_data[-2])
                        for version in affected_versions.split(", "):
                            version = version.lstrip()

                            if version.startswith(base_version):
                                all_cves.add(cve)
                                current_cvss = float(row_data[4])
                                if current_cvss > max_cvss:
                                    max_cvss = current_cvss

            if max_cvss:
                max_severity = cvss_to_severity(max_cvss, 3.1)
             
            # 4. Return the Vulnerability object
            return [Vulnerability(
                cve_id=sorted(list(all_cves)),
                severity=max_severity,
                vendor="Oracle",
                product=context.get("sw_display_name", product_name),
                product_base_version=context.get("base_version"),
                product_fix_version=context.get("product_fix_version"),
                source_id=context.get("source_id"),
                published_date=release_date if release_date else None
            )]

        except Exception as e:
            print(e)
            return []
