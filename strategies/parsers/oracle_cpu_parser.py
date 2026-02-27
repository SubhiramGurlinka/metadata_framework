# oracle_cpu_parser.py

from models import Vulnerability
from utils.get_soup import get_soup
from utils.cvss_to_severity import cvss_to_severity
from strategies.base import PageParser

class OracleCpuParser(PageParser):

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
                if item.strip().lower().startswith(product_name):
                    parts = item.split(": ")
                    if len(parts) != 2:
                        raise ValueError("Invalid format in affected version column")
                    return parts[1]   
        return cell_data

    def parse(self, cpu_url, context):
        try:
            cpu_soup = get_soup(cpu_url, "html.parser")
            if isinstance(cpu_soup, Exception): 
                raise RuntimeError(f"Failed to fetch CPU page: {cpu_soup}")

            product_name = context["product"]
            if not product_name:
                raise ValueError("Context missing 'product'")
            product_name = product_name.lower()
            base_version = str(context["base_version"])
            release_date = context["release_date"]

            if not base_version:
                raise ValueError("Context missing 'base_version'")

            # --------------------------------------
            # Locate relevant tbodies
            # --------------------------------------

            # Oracle DB requires special attention
            its_oracle_db = "oracle database" in product_name
            if its_oracle_db:
                h4_entry = f"{product_name} Risk Matrix"
                product_h4 = cpu_soup.find(
                    "h4", 
                    string=lambda s: s and s.lower() == h4_entry.lower()
                )
                if not product_h4:
                    raise ValueError("Oracle DB Risk Matrix section not found")
                
                products_tbody = product_h4.find_all_next("tbody")
                
                if not products_tbody:
                    raise ValueError("No tbody found for Oracle DB")
                
            else:
                tbodies = cpu_soup.find_all("tbody")
                if not tbodies:
                    raise ValueError("No tbody found in CPU page.")
                
                if len(tbodies) < 2:
                    raise ValueError("CPU page missing product tables, Only Index table found")
                
                products_tbody = tbodies[1:] # Skipping index table

            # ---------------------------------------------------
            # Extract CVEs
            # ---------------------------------------------------
            all_cves = set()
            max_cvss = 0.0
            for product_tbody in products_tbody:
                # Reduced processing by enforcing only 1 table is parsed
                if max_cvss: break
                for row in product_tbody.find_all("tr"):
                    if self.row_contains_product(row, product_name) or its_oracle_db:
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
            
            # For IVR team's comfort
            max_severity = cvss_to_severity(max_cvss, 3.1)
            if not all_cves:
                max_severity = ""

            # 4. Return the Vulnerability object
            return Vulnerability(
                vendor="Oracle",
                cve_id=sorted(list(all_cves)),
                source_id=context.get("source_id"),
                severity=max_severity,
                product_base_version=context.get("base_version"),
                product=context.get("sw_display_name", product_name),
                product_fix_version=context.get("product_fix_version"),
                published_date=release_date if release_date else None
            )

        except Exception as e:
            print(e)
            return 
