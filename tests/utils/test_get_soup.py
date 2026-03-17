import pytest
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup
from utils.get_soup import get_soup

# -----------------------------------------------------------------------------
# TESTS
# -----------------------------------------------------------------------------

@patch("utils.get_soup.get_response")
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


@patch("utils.get_soup.get_response")
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


@patch("utils.get_soup.get_response")
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