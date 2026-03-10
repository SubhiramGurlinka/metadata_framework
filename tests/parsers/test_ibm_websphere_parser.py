import pytest
from strategies.parsers.ibm_websphere_parser import IBMWebSphereTableParser
from models import Vulnerability

def test_calculate_severity():

    parser = IBMWebSphereTableParser()

    assert parser._calculate_severity(2.0) == "Low"
    assert parser._calculate_severity(5.5) == "Medium"
    assert parser._calculate_severity(8.0) == "High"
    assert parser._calculate_severity(9.5) == "Critical"
    assert parser._calculate_severity(None) == "Unknown"

def test_extract_release_date():

    html = """
    <html>
        <h3>Fix Pack 9.0.5.15</h3>
        Fix release date: 15 March 2024
    </html>
    """

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")

    parser = IBMWebSphereTableParser()

    anchor = soup.find(string="Fix Pack 9.0.5.15")

    date = parser._extract_release_date(anchor)

    assert date == "15 March 2024"

# def test_parse_extracts_cves_and_severity():

#     html = """
#     <html>

#         <h3>Fix Pack 9.0.5.15</h3>
#         Fix release date: 15 March 2024

#         <table>
#             <tr>
#                 <td>CVE-2024-1111</td>
#                 <td>CVSS 5.0</td>
#             </tr>
#             <tr>
#                 <td>CVE-2024-2222</td>
#                 <td>CVSS 9.1</td>
#             </tr>
#         </table>

#     </html>
#     """

#     parser = IBMWebSphereTableParser()

#     context = {
#         "product": "websphere",
#         "base_version": "9.0.5",
#         "product_fix_version": "9.0.5.15"
#     }

#     result = parser.parse(html, context)

#     assert isinstance(result, Vulnerability)

#     assert result.cve_id == ["CVE-2024-1111", "CVE-2024-2222"]
#     assert result.severity == "Critical"
#     assert result.vendor == "IBM"
#     assert result.product == "IBM WebSphere Application Server"
#     assert result.product_base_version == "9.0.5"
#     assert result.product_fix_version == "9.0.5.15"
#     assert result.source_id == ["9.0.5.15"]
#     assert result.published_date == "2024-03-15"

def test_parse_header_not_found():

    html = """
    <html>
        <h3>Other Version</h3>
        <table>
            <tr>
                <td>CVE-2024-1111</td>
                <td>CVSS 7.0</td>
            </tr>
        </table>
    </html>
    """

    parser = IBMWebSphereTableParser()

    context = {
        "product_fix_version": "9.0.5.15"
    }

    result = parser.parse(html, context)

    assert result == []

def test_parse_table_not_found():

    html = """
    <html>
        <h3>Fix Pack 9.0.5.15</h3>
        Fix release date: 15 March 2024
    </html>
    """

    parser = IBMWebSphereTableParser()

    context = {
        "product_fix_version": "9.0.5.15"
    }

    result = parser.parse(html, context)

    assert result == []

def test_parse_no_cves():

    html = """
    <html>
        <h3>Fix Pack 9.0.5.15</h3>
        Fix release date: 15 March 2024

        <table>
            <tr>
                <td>No vulnerabilities listed</td>
            </tr>
        </table>
    </html>
    """

    parser = IBMWebSphereTableParser()

    context = {
        "product_fix_version": "9.0.5.15"
    }

    result = parser.parse(html, context)

    assert result == []

# def test_parse_duplicate_cves():

#     html = """
#     <html>

#         <h3><strong>Fix Pack 9.0.5.15</strong></h3>
#         Fix release date: 15 March 2024

#         <table>
#             <tr>
#                 <td>CVE-2024-1111</td>
#                 <td>CVSS 5.0</td>
#             </tr>
#             <tr>
#                 <td>CVE-2024-1111</td>
#                 <td>CVSS 8.0</td>
#             </tr>
#         </table>

#     </html>
#     """

#     parser = IBMWebSphereTableParser()

#     context = {
#         "product": "websphere",
#         "base_version": "9.0.5",
#         "product_fix_version": "9.0.5.15"
#     }

#     result = parser.parse(html, context)
#     print(result)
#     assert isinstance(result, Vulnerability)
#     assert result.cve_id == ["CVE-2024-1111"]

