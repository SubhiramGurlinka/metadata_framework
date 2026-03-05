# # mongodb_parser.py

# import re
# from models import Vulnerability
# from utils.get_soup import get_soup
# from utils.get_response import get_response_text
# from utils.severity_rank import severity_rank
# from strategies.base import PageParser
# from datetime import datetime

# # class MongoDbParser(PageParser):
# #     def get_severity(self, url):
# #         cve_page_text = get_response_text(url)
# #         match = re.search(r'"baseSeverity":\s*"([^"]+)"', cve_page_text)
# #         if match:
# #             return match.group(1).title()
# #         return "None"

# #     def format_date(self, date: str):
# #         dt = datetime.strptime(date.strip(), "%b %d, %Y")
# #         return dt.strftime("%Y-%m-%d")

# #     def parse(self, url, context):
# #         try:
# #             fix_version = context["product_fix_version"]
# #             soup = get_soup(url, "html.parser")
# #             release_date = ""
# #             header = None
# #             all_cves = set()
# #             max_severity = "None"

# #             for tag in soup.find_all(re.compile("^h[2-4]$")):
# #                 if fix_version in tag.get_text(strip=True):
# #                     header = tag
# #                     # Capture the date (if present like "8.2.4 - Jan 27, 2026")
# #                     text = header.get_text(" ", strip=True)
# #                     date = text.split("-", 1)[1].strip()
# #                     release_date = self.format_date(date)

# #                     # Search downwards until the next header to collect CVE hrefs
# #                     for sibling in header.next_siblings:
# #                         for a in sibling.find_all("a", href=True):
# #                             cve_id = a.get_text(strip=True)
# #                             if re.match(r".*CVE-\d{4}-\d{4,7}.*", a.get_text()):
# #                                 # Actual cve_link needs JavaScript support, So got the JSON link
# #                                 cve_link = f"https://cveawg.mitre.org/api/cve/{cve_id}"
# #                                 all_cves.add(cve_id)
# #                                 severity = self.get_severity(cve_link)
# #                                 if severity_rank(severity) > severity_rank(max_severity):
# #                                     max_severity = severity
# #                     break

# #             # For IVR team's comfort
# #             if not all_cves:
# #                 max_severity = ""

# #             # 4. Return the Vulnerability object
# #             return Vulnerability(
# #                 cve_id=sorted(list(all_cves)),
# #                 severity=max_severity,
# #                 vendor="MariaDB",
# #                 product=context.get("sw_display_name", "MariaDB"),
# #                 product_base_version=context.get("base_version"),
# #                 product_fix_version=context.get("product_fix_version"),
# #                 source_id=context.get("product_fix_version"),
# #                 published_date=release_date if release_date else None
# #             )

# #         except Exception as e:
# #             print(e)
# #             return

# import json
# from datetime import datetime
# from utils.get_severity import get_severity_from_cveag_mitre_json


# class MongoDbParser(PageParser):

#     def format_date(self, date: str):
#         try:
#             dt = datetime.strptime(date.strip(), "%b %d, %Y")
#             return dt.strftime("%Y-%m-%d")
#         except ValueError:
#             return None

#     def parse(self, url, context):
#         fix_version = context.get("product_fix_version")
#         if not fix_version:
#             return None

#         soup = get_soup(url, "html.parser")

#         all_cves = set()
#         max_severity = "None"
#         release_date = None

#         version_pattern = re.compile(rf"\b{re.escape(fix_version)}\b")

#         for tag in soup.find_all(re.compile("^h[2-4]$")):
#             if version_pattern.search(tag.get_text()):
#                 text = tag.get_text(" ", strip=True)

#                 date_match = re.search(
#                     r"\b([A-Za-z]{3}\s+\d{1,2},\s+\d{4})\b", text
#                 )
#                 if date_match:
#                     release_date = self.format_date(date_match.group(1))

#                 for sibling in tag.next_siblings:

#                     for a in sibling.find_all("a", href=True):
#                         cve_id = a.get_text(strip=True)

#                         if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
#                             cve_link = f"https://cveawg.mitre.org/api/cve/{cve_id}"
#                             all_cves.add(cve_id)

#                             severity = get_severity_from_cveag_mitre_json(cve_link)
#                             if severity_rank(severity) > severity_rank(max_severity):
#                                 max_severity = severity
#                 break

#         if not all_cves:
#             max_severity = ""

#         return Vulnerability(
#             cve_id=sorted(all_cves),
#             severity=max_severity,
#             vendor="MongoDB",
#             product=context.get("sw_display_name", "MongoDB"),
#             product_base_version=context.get("base_version"),
#             product_fix_version=fix_version,
#             source_id=fix_version,
#             published_date=release_date
#         )


import re
import asyncio
from datetime import datetime
from models import Vulnerability
from strategies.base import PageParser
from utils.get_severity import CVESeverityService
from utils.get_soup import get_soup
from utils.severity_rank import severity_rank


class MongoDbParser(PageParser):
    def format_date(self, date: str):
        try:
            dt = datetime.strptime(date.strip(), "%b %d, %Y")
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return None

    def parse(self, url, context):
        # keeps abstract method contract intact
        return asyncio.run(self._parse_async(url, context))

    async def _parse_async(self, url, context):
        try:
            all_cves = set()
            fix_version = context.get("product_fix_version")
            soup = get_soup(url, "html.parser")
            release_date = None
            version_pattern = re.compile(rf"\b{re.escape(fix_version)}\b")

            header = None
            for tag in soup.find_all(re.compile("^h[2-4]$")):
                if version_pattern.search(tag.get_text()):
                    header = tag
                    break

            if not header:
                raise ValueError("Product verison header not found")

            # Extract release date
            text = header.get_text(" ", strip=True)
            date_match = re.search(
                r"\b([A-Za-z]{3}\s+\d{1,2},\s+\d{4})\b", text
            )
            if date_match:
                release_date = self.format_date(date_match.group(1))

            # Collect CVEs (stop at next header)
            for sibling in header.next_siblings:
                for a in sibling.find_all("a", href=True):
                    cve_id = a.get_text(strip=True)
                    if re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
                        all_cves.add(cve_id)

            severity_service = CVESeverityService()
            severity_map = await severity_service.get_multiple_severities(all_cves)

            max_severity = ""
            for severity in severity_map.values():
                if severity_rank(severity) > severity_rank(max_severity):
                    max_severity = severity

            return Vulnerability(
                cve_id=sorted(all_cves),
                severity=max_severity,
                vendor="MongoDB",
                product=context.get("sw_display_name", "MongoDB"),
                product_base_version=context.get("base_version"),
                product_fix_version=fix_version,
                source_id=fix_version,
                published_date=release_date
            )
        except Exception as e:
            print(e)
            return