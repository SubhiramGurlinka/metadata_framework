import pytest
import asyncio
import httpx
import respx
from unittest.mock import AsyncMock
from utils.get_severity import CVESeverityService

@pytest.fixture
async def client():
    """Shared client fixture for all tests."""
    async with httpx.AsyncClient() as c:
        yield c

@pytest.fixture(autouse=True)
def silent_sleep(monkeypatch):
    """Automatically mock sleep for all tests to avoid recursion and delays."""
    mock = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", mock)
    return mock

@pytest.mark.asyncio
async def test_get_severity_full_success(respx_mock, client):
    """Covers: status == 200, metrics found, cvssV3_1 found."""
    service = CVESeverityService()
    cve_id = "CVE-2026-0001"
    
    mock_data = {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}]}}}
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(return_value=httpx.Response(200, json=mock_data))

    result = await service.get_severity(client, cve_id)
    assert result == "Critical"

@pytest.mark.asyncio
async def test_get_severity_v4_success(respx_mock, client):
    """Covers: status == 200, cvssV4_0 fallback."""
    service = CVESeverityService()
    cve_id = "CVE-2026-0002"
    
    mock_data = {"containers": {"cna": {"metrics": [{"cvssV4_0": {"baseSeverity": "MEDIUM"}}]}}}
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(return_value=httpx.Response(200, json=mock_data))

    result = await service.get_severity(client, cve_id)
    assert result == "Medium"

@pytest.mark.asyncio
async def test_get_severity_200_but_no_metrics(respx_mock, client):
    """Covers: status == 200, but metrics list is empty (returns None)."""
    service = CVESeverityService()
    cve_id = "CVE-2026-0003"
    
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(return_value=httpx.Response(200, json={"containers": {"cna": {"metrics": []}}}))

    result = await service.get_severity(client, cve_id)
    assert result is None

@pytest.mark.asyncio
async def test_get_severity_retry_and_exhaustion(respx_mock, client, silent_sleep):
    """Covers: status == 429 and the loop exhaust (returns None)."""
    service = CVESeverityService(max_retries=2)
    cve_id = "CVE-2026-0004"
    
    # Mocking 429 for all attempts
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(return_value=httpx.Response(429))

    result = await service.get_severity(client, cve_id)
    assert result is None
    assert silent_sleep.call_count == 2 # Proves it retried exactly twice

@pytest.mark.asyncio
async def test_get_severity_unhandled_status(respx_mock, client):
    """Covers: the 'else' block (e.g., 404 Not Found)."""
    service = CVESeverityService()
    cve_id = "CVE-2026-404"
    
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(return_value=httpx.Response(404))

    result = await service.get_severity(client, cve_id)
    assert result is None

@pytest.mark.asyncio
async def test_get_severity_network_error_retry(respx_mock, client, silent_sleep):
    """Covers: except (httpx.TimeoutException, httpx.NetworkError)."""
    service = CVESeverityService(max_retries=2)
    cve_id = "CVE-2026-999"
    
    # Raise error first time, success second time
    route = respx_mock.get(f"{service.BASE_URL}{cve_id}")
    route.side_effect = [
        httpx.ConnectError("Connection failed"),
        httpx.Response(200, json={"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseSeverity": "LOW"}}]}}})
    ]

    result = await service.get_severity(client, cve_id)
    assert result == "Low"
    assert silent_sleep.call_count == 1

@pytest.mark.asyncio
async def test_get_severity_generic_exception(respx_mock, client):
    """Covers: the final 'except Exception' block."""
    service = CVESeverityService()
    cve_id = "CVE-EXCEPTION"
    
    # Force a non-network error (like a TypeError during processing)
    respx_mock.get(f"{service.BASE_URL}{cve_id}").mock(side_effect=TypeError("Unexpected code crash"))

    result = await service.get_severity(client, cve_id)
    assert result is None

@pytest.mark.asyncio
async def test_get_multiple_severities_workflow(respx_mock):
    """Covers: get_multiple_severities and its internal context manager."""
    service = CVESeverityService()
    cve_ids = ["CVE-A", "CVE-B"]

    respx_mock.get(f"{service.BASE_URL}CVE-A").mock(return_value=httpx.Response(200, json={"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseSeverity": "HIGH"}}]}}}))
    respx_mock.get(f"{service.BASE_URL}CVE-B").mock(return_value=httpx.Response(200, json={"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseSeverity": "LOW"}}]}}}))

    results = await service.get_multiple_severities(cve_ids)
    assert results == {"CVE-A": "High", "CVE-B": "Low"}