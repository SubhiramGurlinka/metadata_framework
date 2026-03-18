import pytest
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from utils.session_logic import get_response, async_get_response, _get_or_create_client

# -----------------------------------------------------------------------------
# 1. SYNC LOGIC TESTS (Singleton & get_response)
# -----------------------------------------------------------------------------

@patch("utils.session_logic._client_instance", None) # Force a clean state
@patch("atexit.register")
def test_get_or_create_client_singleton(mock_atexit):
    """
    TARGET: _get_or_create_client (Singleton Pattern)
    SCENARIO: Verifies that multiple calls return the exact same instance and register cleanup.
    """
    # --- ACT ---
    client1 = _get_or_create_client()
    client2 = _get_or_create_client()

    # --- ASSERT ---
    assert client1 is client2
    assert isinstance(client1, httpx.Client)
    mock_atexit.assert_called_once_with(client1.close)


@patch("utils.session_logic._get_or_create_client")
@patch("time.sleep")
def test_sync_get_response_success(mock_sleep, mock_get_client):
    """
    TARGET: get_response (Happy Path)
    SCENARIO: First attempt returns a 200 OK. It should return immediately.
    """
    # --- ARRANGE ---
    mock_client = MagicMock()
    mock_response = MagicMock(status_code=200)
    mock_client.get.return_value = mock_response
    mock_get_client.return_value = mock_client

    # --- ACT ---
    result = get_response("http://fake-url.com")

    # --- ASSERT ---
    assert result == mock_response
    mock_client.get.assert_called_once()
    mock_sleep.assert_not_called() # No retries needed


@patch("utils.session_logic._get_or_create_client")
@patch("time.sleep")
def test_sync_get_response_recovers_after_retry(mock_sleep, mock_get_client):
    """
    TARGET: get_response (Recovery Path)
    SCENARIO: Fails with 500, then succeeds with 200 on the second attempt.
    """
    # --- ARRANGE ---
    mock_client = MagicMock()
    mock_500 = MagicMock(status_code=500)
    mock_200 = MagicMock(status_code=200)
    
    # side_effect allows us to return different responses on subsequent calls
    mock_client.get.side_effect = [mock_500, mock_200]
    mock_get_client.return_value = mock_client

    # --- ACT ---
    result = get_response("http://fake-url.com")

    # --- ASSERT ---
    assert result == mock_200
    assert mock_client.get.call_count == 2
    mock_sleep.assert_called_once_with(1) # Waited 1 second after attempt 0


@patch("utils.session_logic._get_or_create_client")
@patch("time.sleep")
def test_sync_get_response_exhausts_retries_on_exception(mock_sleep, mock_get_client):
    """
    TARGET: get_response (Total Network Failure)
    SCENARIO: Encounters TimeoutException 4 times in a row.
    EXPECTED: Returns None after exhausting all 3 retries (4 total attempts).
    """
    # --- ARRANGE ---
    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.TimeoutException("Timeout")
    mock_get_client.return_value = mock_client

    # --- ACT ---
    result = get_response("http://fake-url.com")

    # --- ASSERT ---
    assert result is None
    assert mock_client.get.call_count == 4
    
    # Check exponential backoff (1s, 2s, 4s)
    assert mock_sleep.call_count == 3
    mock_sleep.assert_any_call(1)
    mock_sleep.assert_any_call(2)
    mock_sleep.assert_any_call(4)


# -----------------------------------------------------------------------------
# 2. ASYNC LOGIC TESTS (async_get_response)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
@patch("asyncio.sleep")
async def test_async_get_response_success(mock_sleep):
    """
    TARGET: async_get_response (Happy Path)
    SCENARIO: AsyncClient returns 200 OK immediately.
    """
    # --- ARRANGE ---
    mock_client = AsyncMock()
    mock_response = MagicMock(status_code=200)
    mock_client.get.return_value = mock_response

    # --- ACT ---
    result = await async_get_response(mock_client, "http://fake-url.com")

    # --- ASSERT ---
    assert result == mock_response
    mock_client.get.assert_called_once()
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
@patch("asyncio.sleep")
async def test_async_get_response_recovers_after_retry(mock_sleep):
    """
    TARGET: async_get_response (Recovery Path)
    SCENARIO: Hits a Rate Limit (429) once, then gets 200 OK.
    """
    # --- ARRANGE ---
    mock_client = AsyncMock()
    mock_429 = MagicMock(status_code=429)
    mock_200 = MagicMock(status_code=200)
    mock_client.get.side_effect = [mock_429, mock_200]

    # --- ACT ---
    result = await async_get_response(mock_client, "http://fake-url.com")

    # --- ASSERT ---
    assert result == mock_200
    assert mock_client.get.call_count == 2
    mock_sleep.assert_called_once_with(1) # Correctly yields to the event loop


@pytest.mark.asyncio
@patch("asyncio.sleep")
async def test_async_get_response_exhausts_retries_on_bad_status(mock_sleep):
    """
    TARGET: async_get_response (Persistent Server Error)
    SCENARIO: Server constantly returns 503.
    EXPECTED: Returns the final 503 response after all retries are exhausted.
    """
    # --- ARRANGE ---
    mock_client = AsyncMock()
    mock_503 = MagicMock(status_code=503)
    mock_client.get.return_value = mock_503

    # --- ACT ---
    result = await async_get_response(mock_client, "http://fake-url.com")

    # --- ASSERT ---
    assert result == mock_503
    assert mock_client.get.call_count == 4
    
    # Check exponential backoff for async sleep
    assert mock_sleep.call_count == 3
    mock_sleep.assert_any_call(1)
    mock_sleep.assert_any_call(2)
    mock_sleep.assert_any_call(4)