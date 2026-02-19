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

@patch("strategies.vendor.mariadb.get_json")
def test_get_release_date_returns_correct_date(mock_get_json):
    # Arrange: Mock get_json to simulate JSON API response
    mock_get_json.return_value = {
        "releases": {
            "10.6.15": {
                "date_of_release": "2024-01-15"
            }
        }
    }

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    # Act
    result = strategy.get_release_date("http://fake-url", "10.6.15")

    # Assert
    mock_get_json.assert_called_once_with("http://fake-url")
    assert result == "2024-01-15"

@patch("strategies.vendor.mariadb.get_json")
def test_get_release_date_handles_missing_version(mock_get_json):
    # Arrange: Return JSON without requested fix_version
    mock_get_json.return_value = {
        "releases": {
            "10.6.14": {
                "date_of_release": "2024-01-01"
            }
        }
    }

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    # Act & Assert: Accessing missing key raises KeyError
    with pytest.raises(KeyError):
        strategy.get_release_date("http://fake-url", "10.6.15")


@patch("strategies.vendor.mariadb.get_json")
def test_get_release_date_returns_none_on_invalid_json(mock_get_json):
    # Arrange: get_json returns None due to error
    mock_get_json.return_value = None

    strategy = MariaDbVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    # Act & Assert: Accessing response when None should raise TypeError or KeyError
    with pytest.raises(TypeError):
        strategy.get_release_date("http://fake-url", "10.6.15")

# ==========================================================
#                   process()
# ==========================================================

def test_process_invokes_parser_with_expected_context():
    # Arrange
    mock_parser = Mock(spec=MariaDbParser)
    expected_vulnerability = Vulnerability(
        cve_id=["CVE-1234-5678"],
        severity="High",
        vendor="MariaDB",
        product="MariaDB",
        product_base_version="10.6",
        product_fix_version="10.6.15",
        source_id="10.6.15",
        published_date="2024-01-15"
    )
    mock_parser.parse.return_value = expected_vulnerability

    software_cfg = {
        "base_date_url": "http://dates/",
        "display_name": "MariaDB"
    }
    vendor_cfg = {}

    strategy = MariaDbVendorStrategy(
        parser=mock_parser,
        software_cfg=software_cfg,
        vendor_cfg=vendor_cfg
    )

    # Mock internal methods so no external call
    strategy.get_url = Mock(return_value="http://product-url")
    strategy.get_release_date = Mock(return_value="2024-01-15")

    # Act
    result = strategy.process(
        product="mariadb",
        base_version="10.6",
        fix_version="10.6.15"
    )

    # Assert
    assert result == expected_vulnerability

    strategy.get_url.assert_called_once_with("10.6")

    strategy.get_release_date.assert_called_once_with(
        "http://dates/10.6",
        "10.6.15"
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