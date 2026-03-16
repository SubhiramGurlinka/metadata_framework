# test_postgresql_strategy.py

import pytest
from unittest.mock import MagicMock, patch
from strategies.vendor.postgresql import PostgreSqlVendorStrategy


@pytest.fixture
def mock_parser():
    parser = MagicMock()
    parser.parse.return_value = ["vulnerability_object"]
    return parser


@pytest.fixture
def postgres_strategy(mock_parser):
    software_cfg = {
        "display_name": "PostgreSQL",
        "base_date_url": "https://www.postgresql.org/docs/release/"
    }

    vendor_cfg = {
        "display_name": "PostgreSQL"
    }

    return PostgreSqlVendorStrategy(
        parser=mock_parser,
        software_cfg=software_cfg,
        vendor_cfg=vendor_cfg
    )


@patch("strategies.vendor.postgresql.get_response_text")
def test_process_flow(mock_get_text, postgres_strategy, mock_parser):
    """Verify process() fetches content and calls parser with correct context."""

    mock_get_text.return_value = "<html>Fake PostgreSQL Advisory</html>"

    with patch.object(postgres_strategy, "get_url", return_value="http://test.com"):
        results = postgres_strategy.process("postgresql", "16", "16.2")

    # get_response_text should be called with URL
    mock_get_text.assert_called_once_with("http://test.com")

    # parser should be called once
    mock_parser.parse.assert_called_once()

    args, kwargs = mock_parser.parse.call_args
    passed_context = args[1]

    assert passed_context["product"] == "postgresql"
    assert passed_context["base_version"] == "16"
    assert passed_context["product_fix_version"] == "16.2"
    assert passed_context["date_url"] == "https://www.postgresql.org/docs/release/16.2"
    assert passed_context["sw_display_name"] == "PostgreSQL"

    assert results == ["vulnerability_object"]


@patch("strategies.vendor.postgresql.get_response_text")
def test_process_empty_response(mock_get_text, postgres_strategy, mock_parser):
    """Test behavior when the page returns empty content."""

    mock_get_text.return_value = ""

    with patch.object(postgres_strategy, "get_url", return_value="http://test.com"):
        results = postgres_strategy.process("postgresql", "16", "16.2")

    mock_parser.parse.assert_called_once()

    args, kwargs = mock_parser.parse.call_args
    html_passed = args[0]

    assert html_passed == ""