# strategies/vendor/redhat.py
import requests
import json
from typing import List
from strategies.base import VendorStrategy

class RedHatVendorStrategy(VendorStrategy):
    def _get_cve_details(self, rhsa_id: str) -> List[dict]:
        cve_api = self.get_config("cve_api_url", "https://access.redhat.com/hydra/rest/securitydata/cve.json")
        r = requests.get(cve_api, params={"advisory": rhsa_id}, timeout=30)
        r.raise_for_status()
        return [{"cve": item["CVE"], "severity": item["severity"]} for item in r.json()]

    def process(self, product: str, base_version: str, fix_version: str):
        search_url = self.get_config("search_url")
        display_name = self.get_config("display_name", product)
        
        # Build filter: portal_product_filter:JBoss\ Enterprise\ Application\ Platform|*|7.4|*
        escaped_name = display_name.replace(" ", "\\ ")
        fq_filter = f"portal_product_filter:{escaped_name}|*|{base_version}|*"
        
        start = 0
        rows = 100
        collected_errata = []

        while True:
            params = {
                "q": "*:*", "start": start, "rows": rows,
                "sort": "portal_publication_date desc",
                "fl": "id,portal_synopsis,portal_severity,portal_publication_date,allTitle",
                "fq": ['documentKind:("Errata") AND portal_advisory_type:("Security Advisory")', fq_filter]
            }
            
            resp = requests.get(search_url, params=params, timeout=30)
            resp.raise_for_status()
            docs = resp.json().get("response", {}).get("docs", [])
            
            if not docs:
                break

            for doc in docs:
                synopsis = doc.get("portal_synopsis", "")
                if fix_version in synopsis:
                    rhsa_id = doc["id"]
                    collected_errata.append({
                        "source_id": rhsa_id,
                        "publication_date": doc.get("portal_publication_date"),
                        "cves": self._get_cve_details(rhsa_id)
                    })
            
            start += rows
            if len(docs) < rows: break

        context = {
            "product": product,
            "display_name": display_name,
            "base_version": base_version,
            "product_fix_version": fix_version
        }

        # Pass the list of errata as a JSON string to the parser
        return self.parser.parse(json.dumps(collected_errata), context)