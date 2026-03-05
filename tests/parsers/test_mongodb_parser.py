import pytest
from unittest.mock import patch, AsyncMock
from strategies.parsers.mongodb_parser import MongoDbParser
from models import Vulnerability


def test_format_date_valid():
    parser = MongoDbParser()
    assert parser.format_date("Jan 10, 2024") == "2024-01-10"


def test_format_date_invalid():
    parser = MongoDbParser()
    assert parser.format_date("invalid date") is None


@patch("strategies.parsers.mongodb_parser.severity_rank")
@patch("strategies.parsers.mongodb_parser.CVESeverityService")
@patch("strategies.parsers.mongodb_parser.get_soup")
def test_parse_extracts_cves_and_returns_vulnerability(
    mock_get_soup, mock_severity_service, mock_severity_rank
):
    html = """
    <html>
        <body>
            <h2>MongoDB 6.0.1 Jan 10, 2024</h2>
            <p>
                <a href="#">CVE-2024-1111</a>
                <a href="#">CVE-2024-2222</a>
            </p>
        </body>
    </html>
    """

    from bs4 import BeautifulSoup
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    mock_service_instance = mock_severity_service.return_value
    mock_service_instance.get_multiple_severities = AsyncMock(
        return_value={
            "CVE-2024-1111": "LOW",
            "CVE-2024-2222": "CRITICAL",
        }
    )

    mock_severity_rank.side_effect = lambda x: {
        "": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }.get(x, 0)

    parser = MongoDbParser()

    context = {
        "product_fix_version": "6.0.1",
        "base_version": "6.0",
        "sw_display_name": "MongoDB"
    }

    result = parser.parse("http://fake-url", context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2024-1111", "CVE-2024-2222"]
    assert result.severity == "CRITICAL"
    assert result.vendor == "MongoDB"
    assert result.product == "MongoDB"
    assert result.product_base_version == "6.0"
    assert result.product_fix_version == "6.0.1"
    assert result.published_date == "2024-01-10"


@patch("strategies.parsers.mongodb_parser.severity_rank")
@patch("strategies.parsers.mongodb_parser.CVESeverityService")
@patch("strategies.parsers.mongodb_parser.get_soup")
def test_parse_without_release_date(
    mock_get_soup, mock_severity_service, mock_severity_rank
):
    html = """
    <html>
        <body>
            <h2>MongoDB 6.0.1</h2>
            <p>
                <a href="#">CVE-2024-3333</a>
            </p>
        </body>
    </html>
    """

    from bs4 import BeautifulSoup
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    mock_service_instance = mock_severity_service.return_value
    mock_service_instance.get_multiple_severities = AsyncMock(
        return_value={"CVE-2024-3333": "HIGH"}
    )

    mock_severity_rank.side_effect = lambda x: {
        "": 0,
        "HIGH": 3
    }.get(x, 0)

    parser = MongoDbParser()

    context = {
        "product_fix_version": "6.0.1",
        "base_version": "6.0",
        "sw_display_name": "MongoDB"
    }

    result = parser.parse("http://fake-url", context)

    assert isinstance(result, Vulnerability)
    assert result.published_date is None


@patch("strategies.parsers.mongodb_parser.CVESeverityService")
@patch("strategies.parsers.mongodb_parser.get_soup")
def test_parse_no_cves(mock_get_soup, mock_severity_service):

    html = """
    <html>
        <body>
            <h2>MongoDB 6.0.1 Jan 10, 2024</h2>
            <p>No vulnerabilities listed</p>
        </body>
    </html>
    """

    from bs4 import BeautifulSoup
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    mock_service_instance = mock_severity_service.return_value
    mock_service_instance.get_multiple_severities = AsyncMock(return_value={})

    parser = MongoDbParser()

    context = {
        "product_fix_version": "6.0.1",
        "base_version": "6.0",
        "sw_display_name": "MongoDB"
    }

    result = parser.parse("http://fake-url", context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == []
    assert result.severity == ""


@patch("strategies.parsers.mongodb_parser.get_soup")
def test_parse_header_not_found(mock_get_soup):

    html = "<html><body><h2>Other Version</h2></body></html>"

    from bs4 import BeautifulSoup
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    parser = MongoDbParser()

    context = {"product_fix_version": "6.0.1"}

    result = parser.parse("http://fake-url", context)

    assert result is None


@patch("strategies.parsers.mongodb_parser.severity_rank")
@patch("strategies.parsers.mongodb_parser.CVESeverityService")
@patch("strategies.parsers.mongodb_parser.get_soup")
def test_parse_filters_invalid_cve(
    mock_get_soup, mock_severity_service, mock_severity_rank
):

    html = """
    <html>
        <body>
            <h2>MongoDB 6.0.1 Jan 10, 2024</h2>
            <p>
                <a href="#">INVALID-CVE</a>
                <a href="#">CVE-2024-9999</a>
            </p>
        </body>
    </html>
    """

    from bs4 import BeautifulSoup
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    mock_service_instance = mock_severity_service.return_value
    mock_service_instance.get_multiple_severities = AsyncMock(
        return_value={"CVE-2024-9999": "MEDIUM"}
    )

    mock_severity_rank.side_effect = lambda x: {
        "": 0,
        "MEDIUM": 2
    }.get(x, 0)

    parser = MongoDbParser()

    context = {
        "product_fix_version": "6.0.1",
        "base_version": "6.0",
        "sw_display_name": "MongoDB"
    }

    result = parser.parse("http://fake-url", context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2024-9999"]


@patch("strategies.parsers.mongodb_parser.get_soup", side_effect=Exception("boom"))
def test_parse_exception_handling(mock_get_soup):

    parser = MongoDbParser()

    context = {"product_fix_version": "6.0.1"}

    result = parser.parse("http://fake-url", context)

    assert result is None