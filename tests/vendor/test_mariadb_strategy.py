# test_mariadb_strategy.py

"""
Docstring for tests.vendor.test_mariadb_strategy

--> Logic:
Given:
    get_url returns X
    get_release_date returns Y

When:
    process() is called

Then:
    parser.parse is called with correct context
    process returns parser result

--> Naming: test_<method>_<condition>_<expected_result>

"""
import pytest
from unittest.mock import patch, Mock
from strategies.vendor.mariadb import MariaDbVendorStrategy
from strategies.parsers.mariadb_parser import MariaDbParser
from models import Vulnerability


# ==========================================================
#               get_release_date()
# ==========================================================

@patch("strategies.vendor.mariadb.format_date")
@patch("strategies.vendor.mariadb.get_response_text")
def test_get_release_date_returns_correct_date(mock_get_text, mock_format_date):

    #  Arrange 
    mock_get_text.return_value = """
    Some content
    Release date ** 15 January 2024
    More text
    """
    mock_format_date.return_value = "2024-01-15"

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    result = strategy.get_release_date("http://fake-url")

    #  Assert 
    mock_get_text.assert_called_once_with("http://fake-url")
    mock_format_date.assert_called_once_with("15 January 2024")
    assert result == "2024-01-15"


@patch("strategies.vendor.mariadb.get_response_text")
def test_get_release_date_returns_none_if_no_release_date(mock_get_text):

    #  Arrange 
    mock_get_text.return_value = "No release information available"

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    result = strategy.get_release_date("http://fake-url")

    #  Assert 
    mock_get_text.assert_called_once_with("http://fake-url")
    assert result is None


@patch("strategies.vendor.mariadb.get_response_text")
def test_get_release_date_handles_empty_response(mock_get_text):

    #  Arrange 
    mock_get_text.return_value = ""

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    result = strategy.get_release_date("http://fake-url")

    #  Assert 
    assert result is None


@patch("strategies.vendor.mariadb.get_response_text")
def test_get_release_date_handles_different_release_date_format(mock_get_text):

    #  Arrange 
    mock_get_text.return_value = "Release date: 6 Nov 2025"

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    result = strategy.get_release_date("http://fake-url")

    #  Assert 
    # format_date will run normally and return ISO format
    assert result == "2025-11-06"


# ==========================================================
#                   process()
# ==========================================================

def test_process_invokes_parser_with_expected_context():

    #  Arrange 
    mock_parser = Mock(spec=MariaDbParser)

    expected_vulnerability = Vulnerability(
        cve_id=["CVE-1234-5678"],
        severity="High",
        vendor="MariaDB",
        product="MariaDB",
        product_base_version="10.6",
        product_fix_version="10.6.15",
        source_id=["10.6.15"],
        published_date="2024-01-15"
    )

    mock_parser.parse.return_value = expected_vulnerability

    software_cfg = {
        "base_date_url": "http://dates/",
        "display_name": "MariaDB"
    }

    strategy = MariaDbVendorStrategy(
        parser=mock_parser,
        software_cfg=software_cfg,
        vendor_cfg={}
    )

    strategy.get_url = Mock(return_value="http://product-url")
    strategy.get_release_date = Mock(return_value="2024-01-15")

    #  Act 
    result = strategy.process(
        product="mariadb",
        base_version="10.6",
        fix_version="10.6.15"
    )

    #  Assert 
    assert result == expected_vulnerability

    strategy.get_url.assert_called_once_with("10.6")

    strategy.get_release_date.assert_called_once_with(
        "http://dates/10.6/10.6.15.md"
    )

    mock_parser.parse.assert_called_once()

    called_url, context = mock_parser.parse.call_args[0]

    assert called_url == "http://product-url"

    assert context == {
        "url": "http://product-url",
        "product": "mariadb",
        "base_version": "10.6",
        "release_date": "2024-01-15",
        "product_fix_version": "10.6.15",
        "sw_display_name": "MariaDB"
    }


def test_process_handles_missing_release_date():

    #  Arrange 
    mock_parser = Mock(spec=MariaDbParser)
    mock_parser.parse.return_value = "parsed"

    strategy = MariaDbVendorStrategy(
        parser=mock_parser,
        software_cfg={
            "base_date_url": "http://dates/",
            "display_name": "MariaDB"
        },
        vendor_cfg={}
    )

    strategy.get_url = Mock(return_value="url")
    strategy.get_release_date = Mock(return_value=None)

    #  Act 
    strategy.process("mariadb", "10.6", "10.6.15")

    #  Assert 
    context = mock_parser.parse.call_args[0][1]
    assert context["release_date"] is None