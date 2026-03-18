# test_mariadb_parser.py

import pytest
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
def test_parse_success_flow(mock_service_class, mock_get_text, parser, context):
    """
    TARGET: Success branch (matching version + multiple CVEs).
    SCENARIO: Verifies regex extraction, version filtering, and max severity ranking 
              through the asyncio.run wrapper.
    """
    # --- ARRANGE ---
    mock_get_text.return_value = (
        "| [CVE-2026-1001] ..... [11.4.1]\n"
        "| [CVE-2026-1002] for [11.4.1]\n"
        "| [CVE-2026-1003] for [11.4.2]\n" # Should be ignored (wrong version)
        "Ignore CVE-2026-9999 for version 10.5.0"
    )
    
    # Mock the async external service correctly for asyncio.run()
    mock_service_instance = mock_service_class.return_value
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
    
    # Verify the service was actually called
    mock_service_instance.get_multiple_severities.assert_called_once()


@patch("strategies.parsers.mariadb_parser.get_response_text")
@patch("strategies.parsers.mariadb_parser.CVESeverityService")
def test_parse_no_matching_cves(mock_service_class, mock_get_text, parser, context):
    """
    TARGET: The 'if all_cves' optimization branch.
    SCENARIO: Text is retrieved but no CVE IDs match the targeted fix_version.
    EXPECTED: Returns a Vulnerability with empty CVEs and NO network calls are made.
    """
    # --- ARRANGE ---
    mock_get_text.return_value = "MariaDB 11.4.1 maintenance release. No security fixes."

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert isinstance(result, Vulnerability)
    assert result.cve_id == []
    assert result.severity == "" 
    
    # Crucial: Verify your optimization works and the service was NEVER instantiated
    mock_service_class.assert_not_called()


@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_empty_text_guard_clause(mock_get_text, parser, context):
    """
    TARGET: Guard clause 'if not text: return'.
    SCENARIO: Utility returns None (simulation of a network error in get_text).
    EXPECTED: Early exit returning None.
    """
    # --- ARRANGE ---
    mock_get_text.return_value = None

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert result is None 


@patch("strategies.parsers.mariadb_parser.get_response_text")
def test_parse_exception_handling(mock_get_text, parser, context, capsys):
    """
    TARGET: The broad 'except Exception as e' block.
    SCENARIO: A runtime error occurs anywhere during parsing.
    EXPECTED: Prints the error to stdout and gracefully returns None.
    """
    # --- ARRANGE ---
    mock_get_text.side_effect = RuntimeError("Service Unavailable")

    # --- ACT ---
    result = parser.parse("https://fake-url.com", context)

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert "Service Unavailable" in captured.out