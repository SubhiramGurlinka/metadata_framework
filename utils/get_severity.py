# get_severity.py

import asyncio
import httpx
from utils.session_logic import async_get_response

class CVESeverityService:
    BASE_URL = "https://cveawg.mitre.org/api/cve/"

    def __init__(self, concurrency_limit=5):
        self.semaphore = asyncio.Semaphore(concurrency_limit)

    async def get_severity(self, client: httpx.AsyncClient, cve_id: str):
        url = f"{self.BASE_URL}{cve_id}"
        
        async with self.semaphore:
            # Pass the shared client into the retry utility
            response = await async_get_response(client, url)

            # First checking if response is None
            if response and response.status_code == 200:
                data = response.json()
                metrics = (
                    data.get("containers", {})
                        .get("cna", {})
                        .get("metrics", [])
                    )
                for metric in metrics:
                    cvss = (
                        metric.get("cvssV4_0") or 
                        metric.get("cvssV3_1") or 
                        metric.get("cvssV3_0")
                    )
                    if cvss and "baseSeverity" in cvss:
                        return cvss["baseSeverity"].title()
            else:
                print(f"Network Error: {cve_id}")
        return 

    async def get_multiple_severities(self, cve_ids):
        """
        The Context Manager lives here! 
        One connection pool is shared across all CVE tasks.
        """
        # Configure the client exactly how we had it in the singleton
        limits = httpx.Limits(
                    max_connections=20, 
                    max_keepalive_connections=10
                )

        async with httpx.AsyncClient(
                http2=True, 
                limits=limits, 
                timeout = httpx.Timeout(10.0),
                headers = {
                    "User-Agent": "VulnerabilityScanner/1.0"
                }
            ) as client:
            tasks = {
                cve_id: asyncio.create_task(self.get_severity(client, cve_id))
                for cve_id in cve_ids
            }
            return {cve_id: await task for cve_id, task in tasks.items()}