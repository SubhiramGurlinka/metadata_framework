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

# import asyncio
# import aiohttp

# class CVESeverityService:
#     """
#     Reusable async CVE severity fetcher.

#     Features:
#     - Concurrency limit
#     - Retry with exponential backoff
#     - Timeout protection
#     """

#     BASE_URL = "https://cveawg.mitre.org/api/cve/"

#     def __init__(self, concurrency_limit=5, max_retries=3, timeout=10):
#         self.semaphore = asyncio.Semaphore(concurrency_limit)
#         self.max_retries = max_retries
#         self.timeout = aiohttp.ClientTimeout(total=timeout)

#     async def get_severity(self, session, cve_id):
#         """
#         Fetch severity for a single CVE ID.
#         Returns severity string or "None".
#         """

#         url = f"{self.BASE_URL}{cve_id}"

#         for attempt in range(self.max_retries):
#             try:
#                 async with self.semaphore:
#                     async with session.get(url, timeout=self.timeout) as response:

#                         if response.status == 200:
#                             data = await response.json()

#                             metrics = (
#                                 data.get("containers", {})
#                                     .get("cna", {})
#                                     .get("metrics", [])
#                             )

#                             for metric in metrics:
#                                 cvss = metric.get("cvssV4_0") or metric.get("cvssV3_1")
#                                 if cvss and "baseSeverity" in cvss:
#                                     return cvss["baseSeverity"].title()

#                             return

#                         elif response.status == 429:
#                             await asyncio.sleep(2 ** attempt)

#                         else:
#                             return 

#             except asyncio.TimeoutError:
#                 await asyncio.sleep(2 ** attempt)

#             except Exception:
#                 return 

#         return 

#     async def get_multiple_severities(self, cve_ids):
#         """
#         Fetch severities concurrently for multiple CVEs.
#         Returns dict {cve_id: severity}
#         """
#         results = {}

#         async with aiohttp.ClientSession() as session:
#             tasks = {
#                 cve_id: asyncio.create_task(self.get_severity(session, cve_id))
#                 for cve_id in cve_ids
#             }
#             for cve_id, task in tasks.items():
#                 results[cve_id] = await task

#         return results

import asyncio
import httpx

class CVESeverityService:
    """
    Reusable async CVE severity fetcher using HTTPX.
    """

    BASE_URL = "https://cveawg.mitre.org/api/cve/"

    def __init__(self, concurrency_limit=5, max_retries=3, timeout=10.0):
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.max_retries = max_retries
        # httpx uses a float or a Timeout object
        self.timeout = httpx.Timeout(timeout)

    async def get_severity(self, client: httpx.AsyncClient, cve_id: str):
        """
        Fetch severity for a single CVE ID using an existing AsyncClient.
        """
        url = f"{self.BASE_URL}{cve_id}"

        for attempt in range(self.max_retries):
            try:
                async with self.semaphore:
                    response = await client.get(url, timeout=self.timeout)

                    if response.status_code == 200:
                        data = response.json()
                        metrics = (
                            data.get("containers", {})
                                .get("cna", {})
                                .get("metrics", [])
                        )

                        for metric in metrics:
                            # httpx makes it easy to check keys or use .get()
                            cvss = metric.get("cvssV4_0") or metric.get("cvssV3_1") or metric.get("cvssV3_0")
                            if cvss and "baseSeverity" in cvss:
                                return cvss["baseSeverity"].title()
                        return

                    elif response.status_code == 429:
                        # Rate limited: Wait and retry
                        await asyncio.sleep(2 ** attempt)

                    else:
                        # Other errors (404, 500, etc.)
                        return

            except (httpx.TimeoutException, httpx.NetworkError):
                await asyncio.sleep(2 ** attempt)
            except Exception:
                return

        return

    async def get_multiple_severities(self, cve_ids):
        """
        Fetch severities concurrently for multiple CVEs.
        """
        results = {}
        
        # httpx uses AsyncClient instead of ClientSession
        async with httpx.AsyncClient(
            headers={"User-Agent": "VulnerabilityScanner/1.0"}
            ) as client:
            tasks = {
                cve_id: asyncio.create_task(self.get_severity(client, cve_id))
                for cve_id in cve_ids
            }
            # Gathering results
            for cve_id, task in tasks.items():
                results[cve_id] = await task

        return results