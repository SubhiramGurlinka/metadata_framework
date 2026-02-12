import pytest
from strategies.base import VendorStrategy, PageParser

# Mock implementations for testing abstract classes
class MockParser(PageParser):
    def parse(self, content, context):
        return []

class MockStrategy(VendorStrategy):
    def get_urls(self, product, base_version):
        return ["http://test.com"]
    def process(self, product, base_version):
        return []

@pytest.fixture
def strategy_setup():
    software_cfg = {"timeout": 30, "retries": 5}
    vendor_cfg = {"timeout": 10, "user_agent": "Mozilla"}
    parser = MockParser()
    return MockStrategy(parser, software_cfg, vendor_cfg)

def test_config_shadowing_software_override(strategy_setup):
    """Software config should override Vendor config."""
    # 'timeout' exists in both; should take software_cfg value (30)
    assert strategy_setup.get_config("timeout") == 30

def test_config_shadowing_vendor_fallback(strategy_setup):
    """Should fall back to Vendor if not in Software."""
    # 'user_agent' only exists in vendor_cfg
    assert strategy_setup.get_config("user_agent") == "Mozilla"

def test_config_shadowing_default(strategy_setup):
    """Should return default if key exists in neither."""
    assert strategy_setup.get_config("missing_key", "default_val") == "default_val"

def test_abstract_enforcement():
    """Verify that you cannot instantiate the ABCs directly."""
    with pytest.raises(TypeError):
        PageParser()
    with pytest.raises(TypeError):
        VendorStrategy(None, {}, {})
def test_config_shadowing_with_none_value(strategy_setup):
    """
    Test if an explicit None in software_cfg overrides vendor_cfg 
    or falls back. (Current logic overrides if key exists).
    """
    strategy_setup.software_cfg["timeout"] = None
    # Because 'timeout' is in software_cfg, it returns None and doesn't reach vendor_cfg
    assert strategy_setup.get_config("timeout") is None

def test_config_shadowing_missing_keys(strategy_setup):
    """Ensure get_config handles keys missing from both dictionaries."""
    assert strategy_setup.get_config("non_existent_key") is None
    assert strategy_setup.get_config("non_existent_key", default="fallback") == "fallback"

def test_registry_value_lookups(strategy_setup):
    """Test direct lookup methods for software and vendor configs."""
    assert strategy_setup.get_registry_value_from_software_cfg("retries") == 5
    assert strategy_setup.get_registry_value_from_vendor_cfg("user_agent") == "Mozilla"
    assert strategy_setup.get_registry_value_from_software_cfg("missing") is None