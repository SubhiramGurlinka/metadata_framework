# strategies/parsers/redhat_parsers.py
import json
from typing import List
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso

class RedHatUnifiedParser(PageParser):
    SEVERITY_RANK = {
        "critical": 4,
        "important": 3,
        "moderate": 2,
        "low": 1
    }

    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        """
        Parses a JSON string containing a list of Red Hat Errata/Advisories.
        """
        errata_list = json.loads(content)
        if not errata_list:
            return []

        all_cves = set()
        all_source_ids = []
        highest_sev_rank = 0
        highest_sev = "low"
        earliest_date = None

        for item in errata_list:
            all_source_ids.append(item["source_id"])
            
            # Date tracking
            pub_date = item.get("publication_date")
            if pub_date:
                if earliest_date is None or pub_date < earliest_date:
                    earliest_date = pub_date

            # CVE and Severity tracking
            for cve in item.get("cves", []):
                all_cves.add(cve["cve"])
                sev = cve.get("severity", "").lower().strip()
                rank = self.SEVERITY_RANK.get(sev, 0)
                if rank > highest_sev_rank:
                    highest_sev_rank = rank
                    highest_sev = sev

        if not all_cves:
            return []

        return Vulnerability(
            cve_id=sorted(list(all_cves)),
            severity=highest_sev.capitalize(),
            vendor="Red Hat",
            product=context.get("display_name", "Red Hat Product"),
            product_base_version=context.get("base_version"),
            product_fix_version=context.get("product_fix_version"),
            source_id=", ".join(sorted(all_source_ids)),
            published_date=normalize_date_to_iso(earliest_date) if earliest_date else None
        )