import pytest
from unittest.mock import patch
from strategies.parsers.mariadb_parser import MariaDbParser
from models import Vulnerability

@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_get_severity_extracts_base_severity(mock_get_response_text):
    # Arrange
    mock_get_response_text.return_value = '''
    {
        "baseSeverity": "HIGH"
    }
    '''
    parser = MariaDbParser()

    # Act
    severity = parser.get_severity("http://fake-url")

    # Assert
    mock_get_response_text.assert_called_once_with("http://fake-url")
    assert severity == "High"

@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_get_severity_returns_none_when_not_present(mock_get_response_text):
    mock_get_response_text.return_value = "{}"

    parser = MariaDbParser()

    severity = parser.get_severity("http://fake-url")

    assert severity == "None"

@patch("strategies.parsers.mariadb_parser.severity_rank")
@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_extracts_cves_and_returns_vulnerability(mock_get_response_text, mock_severity_rank):
    # Arrange
    # - Simulate release notes page text
    mock_get_response_text.side_effect = [
        # First call -> release notes page
        """
        * [CVE-2024-1234](http://example.com): [MariaDB 10.6.15](https://fake.url), [MariaDB 11.8.4](https://fake.url)
        * [CVE-2025-12345](http://example.com): [MariaDB 11.6.15](https://fake.url), [MariaDB 10.6.15](https://fake.url)
        """,
        # Second call -> CVE API JSON of CVE-2024-1234
        '{"baseSeverity": "LOW"}',
        # Third call -> CVE API JSON of CVE-2025-12345
        '{"baseSeverity": "CRITICAL"}'

    ]

    # - Mock severity ranking
    mock_severity_rank.side_effect = lambda x: {
        "None": 0,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }.get(x, 0)

    parser = MariaDbParser()

    context = {
        "release_date": "2024-01-15",
        "product_fix_version": "10.6.15",
        "base_version": "10.6",
        "sw_display_name": "MariaDB"
    }

    # Act
    result = parser.parse("http://release-page", context)

    # Assert
    assert isinstance(result, Vulnerability)

    assert result.cve_id == ["CVE-2024-1234", "CVE-2025-12345"]
    assert result.severity == "Critical"
    assert result.vendor == "MariaDB"
    assert result.product == "MariaDB"
    assert result.product_base_version == "10.6"
    assert result.product_fix_version == "10.6.15"
    assert result.published_date == "2024-01-15"

@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_returns_empty_cve_list_when_no_match(mock_get_response_text):
    # Arrange
    mock_get_response_text.return_value = "No vulnerabilities here"

    parser = MariaDbParser()

    context = {
        "release_date": "2024-01-15",
        "product_fix_version": "10.6.15",
        "base_version": "10.6",
        "sw_display_name": "MariaDB"
    }

    # Act
    result = parser.parse("http://release-page", context)

    # Assert
    assert isinstance(result, Vulnerability)
    assert result.cve_id == []
    assert result.severity == "None"
    assert result.vendor == "MariaDB"
    assert result.product == "MariaDB"
    assert result.product_base_version == "10.6"
    assert result.product_fix_version == "10.6.15"
    assert result.published_date == "2024-01-15"
