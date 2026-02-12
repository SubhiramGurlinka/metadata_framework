import pytest
from unittest.mock import patch
from factory import StrategyFactory
from strategies.vendor.ibm import IBMVendorStrategy
from strategies.parsers.ibm_mq_parsers import IBMMQTableParser

@pytest.fixture
def mock_registry():
    """Provides a controlled registry structure for factory tests."""
    return {
        'vendors': {
            'ibm': {
                'display_name': 'IBM',
                'default_parser_type': 'IBMTableParser',
                'software': {
                    'mq': {
                        'id': 'mq',
                        'parser_type': 'IBM_mq_fixpack_parser',
                        'supported_versions': ['9.1'],
                        'base_urls': {'9.1': 'http://ibm.com/mq91'}
                    }
                }
            }
        }
    }

def test_get_strategy_success(mock_registry):
    with patch('factory.PRODUCT_REGISTRY', mock_registry):
        strategy = StrategyFactory.get_strategy('ibm', 'mq', '9.1')
        
        assert isinstance(strategy, IBMVendorStrategy)
        assert isinstance(strategy.parser, IBMMQTableParser)
        assert strategy.software_cfg['id'] == 'mq'

def test_get_strategy_invalid_vendor(mock_registry):
    with patch('factory.PRODUCT_REGISTRY', mock_registry):
        with pytest.raises(ValueError, match="Vendor 'unknown' is not supported"):
            StrategyFactory.get_strategy('unknown', 'mq', '9.1')

def test_get_strategy_unsupported_version(mock_registry):
    with patch('factory.PRODUCT_REGISTRY', mock_registry):
        with pytest.raises(ValueError, match="Version 10.0 is not supported"):
            StrategyFactory.get_strategy('ibm', 'mq', '10.0')

def test_get_url_retrieval(mock_registry):
    with patch('factory.PRODUCT_REGISTRY', mock_registry):
        url = StrategyFactory.get_url('ibm', 'mq', '9.1')
        assert url == 'http://ibm.com/mq91'