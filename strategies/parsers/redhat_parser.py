# strategies/parsers/redhat_parsers.py

import json
import asyncio
from typing import List
from strategies.base import PageParser
from models import Vulnerability
from strategies.parsers.utils.general_utilities import normalize_date_to_iso
from utils.get_severity import CVESeverityService


class RedHatUnifiedParser(PageParser):

    SEVERITY_RANK = {
        "critical": 4,
        "important": 3,
        "moderate": 2,
        "low": 1,
        "": 0
    }

    def parse(self, content: str, context: dict) -> List[Vulnerability]:

        errata_list = json.loads(content)
        if not errata_list:
            return []

        all_cves = set()
        all_source_ids = []
        earliest_date = None

        highest_sev_rank = -1
        highest_sev = ""

        missing_cves = []

        # ---- First pass: collect data ----
        for item in errata_list:

            all_source_ids.append(item["source_id"])

            advisory_sev = (item.get("severity") or "").lower().strip()
            advisory_rank = self.SEVERITY_RANK.get(advisory_sev, 0)

            if advisory_rank > highest_sev_rank:
                highest_sev_rank = advisory_rank
                highest_sev = advisory_sev

            pub_date = item.get("publication_date")
            if pub_date:
                if earliest_date is None or pub_date < earliest_date:
                    earliest_date = pub_date

            for cve in item.get("cves", []):

                cve_id = cve["cve"]
                all_cves.add(cve_id)

                sev = (cve.get("severity") or "").lower().strip()

                if not sev:
                    missing_cves.append(cve_id)
                    continue

                rank = self.SEVERITY_RANK.get(sev, 0)

                if rank > highest_sev_rank:
                    highest_sev_rank = rank
                    highest_sev = sev

        # ---- Fetch missing severities once ----
        if missing_cves:

            severity_service = CVESeverityService()

            severity_map = asyncio.run(
                severity_service.get_multiple_severities(missing_cves)
            )

            for cve_id in missing_cves:

                sev = (severity_map.get(cve_id) or "").lower().strip()

                rank = self.SEVERITY_RANK.get(sev, 0)

                if rank > highest_sev_rank:
                    highest_sev_rank = rank
                    highest_sev = sev

        if not all_cves:
            return []

        return Vulnerability(
            cve_id=sorted(all_cves),
            severity=highest_sev.capitalize() if highest_sev else "",
            vendor="Red Hat",
            product=context.get("display_name", "Red Hat Product"),
            product_base_version=context.get("base_version"),
            product_fix_version=context.get("product_fix_version"),
            source_id=sorted(all_source_ids, reverse=True),
            published_date=normalize_date_to_iso(earliest_date) if earliest_date else None
        )