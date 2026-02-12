import pytest
from unittest.mock import MagicMock, patch
from strategies.vendor.ibm import IBMVendorStrategy

@pytest.fixture
def mock_parser():
    parser = MagicMock()
    parser.parse.return_value = ["vulnerability_object"]
    return parser

@pytest.fixture
def ibm_strategy(mock_parser):
    # Mocking config dicts
    software_cfg = {"id": "mq"}
    vendor_cfg = {"display_name": "IBM"}
    return IBMVendorStrategy(parser=mock_parser, software_cfg=software_cfg, vendor_cfg=vendor_cfg)

@patch('requests.get')
def test_process_flow(mock_get, ibm_strategy, mock_parser):
    """Verify that process() fetches data and calls the parser with correct context."""
    # Setup Mock Response
    mock_response = MagicMock()
    mock_response.text = "<html>Fake Table</html>"
    mock_get.return_value = mock_response
    
    # We must mock StrategyFactory.get_url because ibm.py imports it inside get_urls
    with patch('factory.StrategyFactory.get_url', return_value="http://test.com"):
        results = ibm_strategy.process("mq", "9.1", "9.1.5")
    
    # Assertions
    mock_get.assert_called_once_with("http://test.com", timeout=15)
    mock_parser.parse.assert_called_once()
    
    # Check if context was passed correctly
    args, kwargs = mock_parser.parse.call_args
    passed_context = args[1]
    assert passed_context["product"] == "mq"
    assert passed_context["product_fix_version"] == "9.1.5"
    assert results == ["vulnerability_object"]

@patch('requests.get')
def test_process_network_failure(mock_get, ibm_strategy):
    """Test behavior when the network request fails."""
    import requests
    mock_get.side_effect = requests.exceptions.Timeout()
    
    with patch('factory.StrategyFactory.get_url', return_value="http://test.com"):
        with pytest.raises(requests.exceptions.Timeout):
            ibm_strategy.process("mq", "9.1", "9.1.5")