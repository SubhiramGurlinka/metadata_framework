# test_ibm_mq_parser.py

import pytest
from strategies.parsers.ibm_mq_parsers import IBMMQTableParser
from models import Vulnerability


def test_calculate_severity():
    parser = IBMMQTableParser()

    assert parser._calculate_severity(2.0) == "Low"
    assert parser._calculate_severity(5.0) == "Medium"
    assert parser._calculate_severity(8.0) == "High"
    assert parser._calculate_severity(9.5) == "Critical"
    assert parser._calculate_severity(None) == "Unknown"


def test_get_release_date():
    parser = IBMMQTableParser()

    html = """
    <html>
        <table>
            <tr>
                <th>Version</th>
                <th>Release Date</th>
            </tr>
            <tr>
                <td>9.3.4</td>
                <td>28 July 2025</td>
            </tr>
        </table>
    </html>
    """

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")

    date = parser._get_release_date(soup, "9.3.4")

    assert date == "28 July 2025"


def test_parse_extracts_cves_and_severity():

    html = """
    <html>
        <table>
            <tr>
                <th>Version</th>
                <th>Release Date</th>
            </tr>
            <tr>
                <td>9.3.4</td>
                <td>28 July 2025</td>
            </tr>
        </table>

        <h3>IBM MQ Security Bulletin 9.3.4</h3>

        <table>
            <tr>
                <td>CVE-2024-1111 CVSS base score 5.0</td>
            </tr>
            <tr>
                <td>CVE-2024-2222 CVSS base score 9.1</td>
            </tr>
        </table>
    </html>
    """

    parser = IBMMQTableParser()

    context = {
        "product": "IBM MQ",
        "base_version": "9.3",
        "product_fix_version": "9.3.4"
    }

    result = parser.parse(html, context)

    assert isinstance(result, Vulnerability)

    assert "CVE-2024-1111" in result.cve_id
    assert "CVE-2024-2222" in result.cve_id
    assert result.severity == "Critical"
    assert result.vendor == "IBM"
    assert result.product == "IBM MQ"
    assert result.product_base_version == "9.3"
    assert result.product_fix_version == "9.3.4"
    assert result.source_id == ["9.3.4"]
    assert result.published_date is not None


def test_parse_no_cves():

    html = """
    <html>
        <h3>IBM MQ Security Bulletin 9.3.4</h3>
        <table>
            <tr>
                <td>No vulnerabilities listed</td>
            </tr>
        </table>
    </html>
    """

    parser = IBMMQTableParser()

    context = {
        "product": "mq",
        "base_version": "9.3",
        "product_fix_version": "9.3.4"
    }

    result = parser.parse(html, context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == []


def test_parse_header_not_found():

    html = """
    <html>
        <h3>Other Product 9.3.4</h3>
        <table>
            <tr>
                <td>CVE-2024-1111 CVSS base score 5.0</td>
            </tr>
        </table>
    </html>
    """

    parser = IBMMQTableParser()

    context = {
        "product_fix_version": "9.3.4"
    }

    result = parser.parse(html, context)

    assert result == []


def test_parse_table_not_found():

    html = """
    <html>
        <h3>IBM MQ Security Bulletin 9.3.4</h3>
    </html>
    """

    parser = IBMMQTableParser()

    context = {
        "product_fix_version": "9.3.4"
    }

    result = parser.parse(html, context)

    assert result == []


def test_parse_multiple_rows_same_cve():

    html = """
    <html>

        <h3>IBM MQ Security Bulletin 9.3.4</h3>

        <table>
            <tr>
                <td>CVE-2024-1111 CVSS base score 5.0</td>
            </tr>
            <tr>
                <td>CVE-2024-1111 CVSS base score 8.0</td>
            </tr>
        </table>

    </html>
    """

    parser = IBMMQTableParser()

    context = {
        "product": "IBM MQ",
        "base_version": "9.3",
        "product_fix_version": "9.3.4"
    }

    result = parser.parse(html, context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2024-1111"]