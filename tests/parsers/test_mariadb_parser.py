import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from strategies.parsers.mariadb_parser import MariaDbParser
from models import Vulnerability

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture
def parser():
    """Provides a fresh instance of the MariaDbParser."""
    return MariaDbParser()

@pytest.fixture
def context():
    """Provides a standard context dictionary for MariaDB parsing."""
    return {
        "release_date": "2026-03-17",
        "product_fix_version": "11.4.1",
        "base_version": "11.4",
        "sw_display_name": "MariaDB Server"
    }

# -----------------------------------------------------------------------------
# TEST CASES
# -----------------------------------------------------------------------------

@patch("strategies.parsers.mariadb_parser.get_response_text")
@patch("strategies.parsers.mariadb_parser.CVESeverityService")
def test_parse_success_flow(mock_service, mock_get_text, parser, context):
    """
    TARGET: Success branch (matching version + multiple CVEs).
    SCENARIO: Verifies regex extraction, version filtering, and max severity ranking.
    """
    # --- ARRANGE ---
    mock_get_text.return_value = (
        "| [CVE-2026-1001] ..... [11.4.1]\n"
        "| [CVE-2026-1002] for [11.4.1]\n"
        "| [CVE-2026-1003] for [11.4.2]\n"
        "Ignore CVE-2026-9999 for version 10.5.0"
    )
    
    # Mock the async external service
    mock_service_instance = mock_service.return_value
    mock_service_instance.get_multiple_severities = AsyncMock(return_value={
        "CVE-2026-1001": "Critical",
        "CVE-2026-1002": "Medium"
    })

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2026-1001", "CVE-2026-1002"] # Check sorting
    assert result.severity == "Critical"
    assert result.vendor == "MariaDB"
    assert result.published_date == "2026-03-17"


@patch("strategies.parsers.mariadb_parser.get_response_text")
@patch("strategies.parsers.mariadb_parser.CVESeverityService")
def test_parse_no_matching_cves(mock_service, mock_get_text, parser, context):
    """
    TARGET: The 'if not all_cves' branch.
    SCENARIO: Text is retrieved but no CVE IDs are linked to the targeted fix_version.
    """
    # --- ARRANGE ---
    mock_get_text.return_value = "MariaDB 11.4.1 maintenance release. No security fixes."
    mock_service.return_value.get_multiple_severities = AsyncMock(return_value={})

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert result.cve_id == []
    assert result.severity == "" # Tests the IVR team comfort check


@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_empty_text_guard_clause(mock_get_text, parser, context):
    """
    TARGET: Guard clause 'if not text: raise ValueError'.
    SCENARIO: Utility returns None or empty string (simulation of 404).
    """
    # --- ARRANGE ---
    mock_get_text.return_value = None

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert result is None # Should trigger the except Exception block


@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_exception_handling(mock_get_text, parser, context, capsys):
    """
    TARGET: Generic 'except Exception as e' and 'print(e)'.
    SCENARIO: A runtime error (like a network timeout) occurs during parsing.
    """
    # --- ARRANGE ---
    mock_get_text.side_effect = RuntimeError("Service Unavailable")

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert "Service Unavailable" in captured.out