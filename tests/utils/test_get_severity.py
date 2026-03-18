# test_get_severity.py

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from utils.get_severity import CVESeverityService

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture
def severity_service():
    """Provides a fresh instance of the CVESeverityService with a small concurrency limit."""
    return CVESeverityService(concurrency_limit=2)

@pytest.fixture
def mock_httpx_client():
    """Provides a mock HTTPX AsyncClient."""
    return AsyncMock()

# -----------------------------------------------------------------------------
# TEST CASES: get_severity()
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
@patch("utils.get_severity.async_get_response")
async def test_get_severity_success_flow(mock_get_response, severity_service, mock_httpx_client):
    """
    TARGET: get_severity (Happy Path)
    SCENARIO: API returns 200 OK with valid CVSS v3.1 data.
    """
    # --- ARRANGE ---
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "containers": {
            "cna": {
                "metrics": [
                    {"cvssV3_1": {"baseSeverity": "CRITICAL"}}
                ]
            }
        }
    }
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = await severity_service.get_severity(mock_httpx_client, "CVE-2024-1234")

    # --- ASSERT ---
    mock_get_response.assert_called_once_with(mock_httpx_client, "https://cveawg.mitre.org/api/cve/CVE-2024-1234")
    assert result == "Critical"


@pytest.mark.asyncio
@patch("utils.get_severity.async_get_response")
async def test_get_severity_missing_metrics_returns_none(mock_get_response, severity_service, mock_httpx_client):
    """
    TARGET: get_severity (Missing Data)
    SCENARIO: API returns 200 OK, but the JSON has no metrics array.
    """
    # --- ARRANGE ---
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"containers": {"cna": {}}} 
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = await severity_service.get_severity(mock_httpx_client, "CVE-2024-1234")

    # --- ASSERT ---
    assert result is None


@pytest.mark.asyncio
@patch("utils.get_severity.async_get_response")
async def test_get_severity_non_200_status(mock_get_response, severity_service, mock_httpx_client, capsys):
    """
    TARGET: get_severity (Error Path)
    SCENARIO: API returns a 404 or 500 error, falling into the 'else' block.
    """
    # --- ARRANGE ---
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = await severity_service.get_severity(mock_httpx_client, "CVE-2024-0000")

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    # Now matches your updated else block print statement
    assert "Network Error: CVE-2024-0000" in captured.out


@pytest.mark.asyncio
@patch("utils.get_severity.async_get_response")
async def test_get_severity_handles_none_response(mock_get_response, severity_service, mock_httpx_client, capsys):
    """
    TARGET: Guard clause for None response (the bug you just fixed).
    SCENARIO: async_get_response exhausts retries and returns None (Network timeout).
    """
    # --- ARRANGE ---
    mock_get_response.return_value = None

    # --- ACT ---
    result = await severity_service.get_severity(mock_httpx_client, "CVE-2024-9999")

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    # Verifies that a None response correctly falls into the else block without throwing an AttributeError
    assert "Network Error: CVE-2024-9999" in captured.out


# -----------------------------------------------------------------------------
# TEST CASES: get_multiple_severities()
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
@patch("utils.get_severity.httpx.AsyncClient")
async def test_get_multiple_severities_orchestration(mock_async_client_class, severity_service):
    """
    TARGET: get_multiple_severities
    SCENARIO: Verifies the context manager setup and that multiple tasks are awaited and gathered.
    """
    # --- ARRANGE ---
    cve_ids = ["CVE-2024-0001", "CVE-2024-0002"]
    
    # Mock the async context manager (__aenter__ and __aexit__)
    mock_client_instance = AsyncMock()
    mock_async_client_class.return_value.__aenter__.return_value = mock_client_instance
    
    # Patch the instance method 'get_severity' to avoid network logic
    async def mock_get_severity_impl(client, cve_id):
        return "High" if cve_id == "CVE-2024-0001" else "Medium"
    
    severity_service.get_severity = AsyncMock(side_effect=mock_get_severity_impl)

    # --- ACT ---
    result = await severity_service.get_multiple_severities(cve_ids)

    # --- ASSERT ---
    assert result == {
        "CVE-2024-0001": "High",
        "CVE-2024-0002": "Medium"
    }
    
    mock_async_client_class.assert_called_once()
    call_kwargs = mock_async_client_class.call_args.kwargs
    assert call_kwargs["http2"] is True
    
    assert severity_service.get_severity.call_count == 2