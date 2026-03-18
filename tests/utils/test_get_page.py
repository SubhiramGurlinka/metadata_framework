import pytest
from unittest.mock import patch, Mock, MagicMock
from bs4 import BeautifulSoup
from utils.get_page import get_soup, get_json, get_response_text

# -----------------------------------------------------------------------------
# TESTS
# -----------------------------------------------------------------------------

@patch("utils.get_page.get_response")
def test_get_soup_success(mock_get_response):
    """
    TARGET: Success branch (Response 200).
    SCENARIO: Verifies that HTML content is correctly converted into a BeautifulSoup object.
    """
    # --- ARRANGE ---
    mock_url = "https://example.com"
    mock_html = "<html><body><h1>Hello World</h1></body></html>"
    
    mock_response = MagicMock()
    mock_response.content = mock_html
    mock_response.status_code = 200
    mock_get_response.return_value = mock_response

    # --- ACT ---
    soup = get_soup(mock_url, "html.parser")

    # --- ASSERT ---
    assert isinstance(soup, BeautifulSoup)
    assert soup.find("h1").text == "Hello World"
    mock_response.raise_for_status.assert_called_once()


@patch("utils.get_page.get_response")
def test_get_soup_http_error(mock_get_response, capsys):
    """
    TARGET: Error branch (e.g., 404 Not Found).
    SCENARIO: Verifies that raise_for_status() triggers the exception block.
    """
    # --- ARRANGE ---
    mock_response = MagicMock()
    # Simulate an HTTPError when raise_for_status is called
    from requests.exceptions import HTTPError
    mock_response.raise_for_status.side_effect = HTTPError("404 Client Error")
    mock_get_response.return_value = mock_response

    # --- ACT ---
    result = get_soup("https://example.com/bad-page", "html.parser")

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert "404 Client Error" in captured.out


@patch("utils.get_page.get_response")
def test_get_soup_generic_exception(mock_get_response, capsys):
    """
    TARGET: Generic 'except Exception as e' block.
    SCENARIO: Verifies handling of non-HTTP errors like ConnectionTimeouts.
    """
    # --- ARRANGE ---
    mock_get_response.side_effect = Exception("Connection Refused")

    # --- ACT ---
    result = get_soup("https://unreachable.url", "html.parser")

    # --- ASSERT ---
    assert result is None
    captured = capsys.readouterr()
    assert "Connection Refused" in captured.out

# ==========================================================
#                   Successful JSON Response
# ==========================================================

@patch("utils.get_page.get_response")
def test_get_json_returns_json_on_success(mock_get_response):
    # -------- Arrange --------
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"status": "ok"}

    mock_get_response.return_value = mock_response

    url = "http://fake-api"

    # -------- Act --------
    result = get_json(url)

    # -------- Assert --------
    mock_get_response.assert_called_once_with(url)
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()

    assert result == {"status": "ok"}


# ==========================================================
#                   HTTP Error Handling
# ==========================================================

@patch("utils.get_page.get_response")
def test_get_json_returns_none_on_http_error(mock_get_response):
    # -------- Arrange --------
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = Exception("HTTP error")

    mock_get_response.return_value = mock_response

    url = "http://fake-api"

    # -------- Act --------
    result = get_json(url)

    # -------- Assert --------
    assert result is None


# ==========================================================
#                   JSON Parsing Error
# ==========================================================

@patch("utils.get_page.get_response")
def test_get_json_returns_none_on_invalid_json(mock_get_response):
    # -------- Arrange --------
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError("Invalid JSON")

    mock_get_response.return_value = mock_response

    url = "http://fake-api"

    # -------- Act --------
    result = get_json(url)

    # -------- Assert --------
    assert result is None


# ==========================================================
#                   Request Failure
# ==========================================================

@patch("utils.get_page.get_response")
def test_get_json_returns_none_when_request_fails(mock_get_response):
    # -------- Arrange --------
    mock_get_response.side_effect = Exception("Network error")

    url = "http://fake-api"

    # -------- Act --------
    result = get_json(url)

    # -------- Assert --------
    assert result is None

# -----------------------------------------------------------------------------
# TESTS
# -----------------------------------------------------------------------------

@patch("utils.get_page.get_response")
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


@patch("utils.get_page.get_response")
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


@patch("utils.get_page.get_response")
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