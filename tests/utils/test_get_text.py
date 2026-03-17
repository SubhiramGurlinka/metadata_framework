import pytest
from unittest.mock import patch, MagicMock
from utils.get_text import get_response_text

# -----------------------------------------------------------------------------
# TESTS
# -----------------------------------------------------------------------------

@patch("utils.get_text.get_response")
def test_get_response_text_success(mock_get_response):
    """
    TARGET: Success branch (Response 200).
    SCENARIO: Verifies that the raw .text property of the response is returned.
    """
    # --- ARRANGE ---
    mock_url = "https://example.com/api/data"
    expected_content = "This is the raw response text."
    
    mock_response = MagicMock()
    mock_response.text = expected_content
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = get_response_text(mock_url)

    # --- ASSERT ---
    assert result == expected_content
    mock_response.raise_for_status.assert_called_once()


@patch("utils.get_text.get_response")
def test_get_response_text_http_error(mock_get_response, capsys):
    """
    TARGET: Exception handling for HTTP errors (via raise_for_status).
    SCENARIO: Verifies that a 403 Forbidden correctly logs the custom error string.
    """
    # --- ARRANGE ---
    mock_url = "https://example.com/secret"
    mock_response = MagicMock()
    
    from requests.exceptions import HTTPError
    mock_response.raise_for_status.side_effect = HTTPError("403 Forbidden")
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = get_response_text(mock_url)

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert f"Request failed for {mock_url}: 403 Forbidden" in captured.out


@patch("utils.get_text.get_response")
def test_get_response_text_generic_exception(mock_get_response, capsys):
    """
    TARGET: Generic 'except Exception as e' block.
    SCENARIO: Verifies handling of connection-level failures like DNS timeouts.
    """
    # --- ARRANGE ---
    mock_url = "https://unreachable-site.com"
    mock_get_response.side_effect = Exception("Connection Timed Out")

    # --- ACT ---
    result = get_response_text(mock_url)

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert f"Request failed for {mock_url}: Connection Timed Out" in captured.out