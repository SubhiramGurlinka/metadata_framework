import pytest
import json
from registry import PRODUCT_REGISTRY

def test_registry_structure_root():
    """Ensure the registry has the main 'vendors' key."""
    assert "vendors" in PRODUCT_REGISTRY
    assert len(PRODUCT_REGISTRY["vendors"]) >= 3  # IBM, RedHat, Apache

@pytest.mark.parametrize("vendor_name", ["ibm", "redhat", "apache"])
def test_vendor_requirements(vendor_name):
    """Each vendor must have a display name and software defined."""
    vendor_data = PRODUCT_REGISTRY["vendors"][vendor_name]
    assert "display_name" in vendor_data
    assert "software" in vendor_data
    assert isinstance(vendor_data["software"], dict)

def test_software_version_consistency():
    """Check that supported_versions have corresponding URLs."""
    tomcat = PRODUCT_REGISTRY["vendors"]["apache"]["software"]["tomcat"]
    supported = tomcat["supported_versions"]
    urls = tomcat["base_urls"]
    
    for version in supported:
        assert version in urls, f"Version {version} missing from base_urls"

def test_parser_fallback_logic():
    """
    Verify parser resolution logic: software specific OR vendor default.
    This mimics the logic that your Factory will eventually use.
    """
    vendors = PRODUCT_REGISTRY["vendors"]
    
    # Apache Tomcat has a specific parser
    assert "parser_type" in vendors["apache"]["software"]["tomcat"]
    
    # RedHat JBoss does NOT have a specific parser, should use vendor default
    jboss = vendors["redhat"]["software"]["jboss"]
    assert "parser_type" not in jboss
    assert "default_parser_type" in vendors["redhat"]