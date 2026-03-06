# get_severity.py

# from utils.get_response import get_response_text
# import json

# def get_severity_from_cveag_mitre_json(url):
#         """
#         Function to parse cveag.mitre json version of a cve 
#         metadata to get the severity in predictable way
#         """
#         try:
#             response_text = get_response_text(url)
#             data = json.loads(response_text)

#             metrics = (
#                 data.get("containers", {})
#                     .get("cna", {})
#                     .get("metrics", [])
#             )

#             for metric in metrics:
#                 cvss = metric.get("cvssV4_0") or metric.get("cvssV3_1")
#                 if cvss and "baseSeverity" in cvss:
#                     return cvss["baseSeverity"].title()

#         except Exception:
#             pass

#         return "None"

import asyncio
import aiohttp


class CVESeverityService:
    """
    Reusable async CVE severity fetcher.

    Features:
    - Concurrency limit
    - Retry with exponential backoff
    - Timeout protection
    """

    BASE_URL = "https://cveawg.mitre.org/api/cve/"

    def __init__(self, concurrency_limit=5, max_retries=3, timeout=10):
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.max_retries = max_retries
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def get_severity(self, session, cve_id):
        """
        Fetch severity for a single CVE ID.
        Returns severity string or "None".
        """

        url = f"{self.BASE_URL}{cve_id}"

        for attempt in range(self.max_retries):
            try:
                async with self.semaphore:
                    async with session.get(url, timeout=self.timeout) as response:

                        if response.status == 200:
                            data = await response.json()

                            metrics = (
                                data.get("containers", {})
                                    .get("cna", {})
                                    .get("metrics", [])
                            )

                            for metric in metrics:
                                cvss = metric.get("cvssV4_0") or metric.get("cvssV3_1")
                                if cvss and "baseSeverity" in cvss:
                                    return cvss["baseSeverity"].title()

                            return "None"

                        elif response.status == 429:
                            await asyncio.sleep(2 ** attempt)

                        else:
                            return "None"

            except asyncio.TimeoutError:
                await asyncio.sleep(2 ** attempt)

            except Exception:
                return "None"

        return "None"

    async def get_multiple_severities(self, cve_ids):
        """
        Fetch severities concurrently for multiple CVEs.
        Returns dict {cve_id: severity}
        """

        results = {}

        async with aiohttp.ClientSession() as session:
            tasks = {
                cve_id: asyncio.create_task(self.get_severity(session, cve_id))
                for cve_id in cve_ids
            }

            for cve_id, task in tasks.items():
                results[cve_id] = await task

        return results