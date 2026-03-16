# test_postgresql_parser.py

import pytest
from unittest.mock import patch

from strategies.parsers.postgresql_parser import PostgreSqlParser
from models import Vulnerability

@patch("strategies.parsers.postgresql_parser.get_response_text")
def test_get_release_date(mock_get_text):

    html = """
    <html>
        <p><strong>Release date:</strong> 2024-03-10</p>
    </html>
    """

    mock_get_text.return_value = html

    parser = PostgreSqlParser()

    date = parser._get_release_date("http://fake-url")

    assert date == "2024-03-10"

@patch("strategies.parsers.postgresql_parser.get_response_text")
def test_parse_extracts_cves(mock_get_text):

    release_page = """
    <html>
        <p>Release date: 2024-03-10</p>
    </html>
    """

    mock_get_text.return_value = release_page

    html = """
    <html>

        <h3>Known PostgreSQL Security Vulnerabilities in Supported Versions</h3>

        <table>
            <tr>
                <th>Version</th>
                <th>CVE</th>
                <th>Description</th>
                <th>CVSS</th>
            </tr>

            <tr>
                <td>16.2</td>
                <td>CVE-2024-1111</td>
                <td>Test vulnerability</td>
                <td>7.5</td>
            </tr>

            <tr>
                <td>16.2</td>
                <td>CVE-2024-2222</td>
                <td>Another vulnerability</td>
                <td>9.1</td>
            </tr>

        </table>

    </html>
    """

    parser = PostgreSqlParser()

    context = {
        "product_fix_version": "16.2",
        "base_version": "16",
        "sw_display_name": "PostgreSQL",
        "date_url": "http://fake-url"
    }

    result = parser.parse(html, context)

    assert isinstance(result, Vulnerability)

    assert result.cve_id == ["CVE-2024-1111", "CVE-2024-2222"]
    assert result.vendor == "PostgreSQL"
    assert result.product == "PostgreSQL"
    assert result.product_base_version == "16"
    assert result.product_fix_version == "16.2"
    assert result.source_id == ["16.2"]
    assert result.published_date == "2024-03-10"

def test_parse_header_not_found():

    html = """
    <html>
        <h3>Other Section</h3>
    </html>
    """

    parser = PostgreSqlParser()

    context = {
        "product_fix_version": "16.2"
    }

    result = parser.parse(html, context)

    assert result is None

@patch("strategies.parsers.postgresql_parser.get_response_text")
def test_parse_table_not_found(mock_get_text):

    mock_get_text.return_value = ""

    html = """
    <html>
        <h3>Known PostgreSQL Security Vulnerabilities in Supported Versions</h3>
    </html>
    """

    parser = PostgreSqlParser()

    context = {
        "product_fix_version": "16.2",
        "date_url": "http://fake-url",
        "base_version": "16"
    }

    result = parser.parse(html, context)

    assert result == []

@patch("strategies.parsers.postgresql_parser.get_response_text")
def test_parse_no_cves(mock_get_text):

    mock_get_text.return_value = "<p>Release date: 2024-03-10</p>"

    html = """
    <html>

        <h3>Known PostgreSQL Security Vulnerabilities in Supported Versions</h3>

        <table>
            <tr>
                <td>16.2</td>
                <td>No vulnerabilities</td>
                <td>-</td>
                <td>-</td>
            </tr>
        </table>

    </html>
    """

    parser = PostgreSqlParser()

    context = {
        "product_fix_version": "16.2",
        "date_url": "http://fake-url",
        "base_version": "16"
    }

    result = parser.parse(html, context)

    assert result.cve_id == []

@patch("strategies.parsers.postgresql_parser.get_response_text")
def test_parse_duplicate_cves(mock_get_text):

    mock_get_text.return_value = "<p>Release date: 2024-03-10</p>"

    html = """
    <html>

        <h3>Known PostgreSQL Security Vulnerabilities in Supported Versions</h3>

        <table>
            <tr>
                <td>16.2</td>
                <td>CVE-2024-1111</td>
                <td>-</td>
                <td>5.0</td>
            </tr>

            <tr>
                <td>16.2</td>
                <td>CVE-2024-1111</td>
                <td>-</td>
                <td>8.0</td>
            </tr>

        </table>

    </html>
    """

    parser = PostgreSqlParser()

    context = {
        "product_fix_version": "16.2",
        "base_version": "16",
        "sw_display_name": "PostgreSQL",
        "date_url": "http://fake-url"
    }

    result = parser.parse(html, context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2024-1111"]

