import pytest
from unittest.mock import patch, Mock
from utils.get_json import get_json


# ==========================================================
#                   Successful JSON Response
# ==========================================================

@patch("utils.get_json.get_response")
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

@patch("utils.get_json.get_response")
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

@patch("utils.get_json.get_response")
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

@patch("utils.get_json.get_response")
def test_get_json_returns_none_when_request_fails(mock_get_response):
    # -------- Arrange --------
    mock_get_response.side_effect = Exception("Network error")

    url = "http://fake-api"

    # -------- Act --------
    result = get_json(url)

    # -------- Assert --------
    assert result is None