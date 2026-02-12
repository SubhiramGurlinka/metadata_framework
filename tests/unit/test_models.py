import pytest
from pydantic import ValidationError
from models import Vulnerability

def test_vulnerability_creation_success():
    """Verify a valid vulnerability object can be created."""
    data = {
        "cve_id": ["CVE-2023-1234"],
        "severity": "High",
        "published_date": "2023-10-27",
        "vendor": "Apache",
        "product": "Tomcat",
        "product_base_version": "9.0",
        "product_fix_version": "9.0.82"
    }
    vuln = Vulnerability(**data)
    assert vuln.published_date == "2023-10-27"
    assert "CVE-2023-1234" in vuln.cve_id

def test_vulnerability_immutability():
    """Ensure frozen=True prevents modification."""
    vuln = Vulnerability(
        cve_id=["CVE-1"], severity="Low", vendor="V", 
        product="P", product_base_version="1", product_fix_version="2"
    )
    with pytest.raises(ValidationError):
        vuln.severity = "High"

@pytest.mark.parametrize("invalid_date", [
    "27-10-2023",        # Wrong format
    "2023/10/27",        # Wrong separator
    "2023-13-01",        # Invalid month
    "2023-02-30",        # Invalid day (Feb 30)
    "not-a-date"         # Garbage string
])
def test_vulnerability_date_validation_failures(invalid_date):
    """Test the regex and calendar validation for published_date."""
    data = {
        "cve_id": ["CVE-1"], "severity": "H", "vendor": "V", 
        "product": "P", "product_base_version": "1", "product_fix_version": "2",
        "published_date": invalid_date
    }
    with pytest.raises(ValueError) as excinfo:
        Vulnerability(**data)
    assert "published_date" in str(excinfo.value)

def test_vulnerability_cve_id_as_list():
    """Ensure cve_id rejects single strings and requires a list."""
    data = {
        "cve_id": "CVE-2023-1234", # Should be ["CVE-2023-1234"]
        "severity": "High", "vendor": "V", "product": "P",
        "product_base_version": "1", "product_fix_version": "2"
    }
    with pytest.raises(ValidationError):
        Vulnerability(**data)

def test_vulnerability_optional_fields():
    """Verify that optional fields can be omitted safely."""
    data = {
        "cve_id": ["CVE-1"], "severity": "Medium", "vendor": "V",
        "product": "P", "product_base_version": "1", "product_fix_version": "2"
    }
    vuln = Vulnerability(**data)
    assert vuln.published_date is None
    assert vuln.source_id is None

def test_vulnerability_empty_cve_list():
    """Verify behavior with an empty CVE list."""
    data = {
        "cve_id": [], "severity": "Low", "vendor": "V",
        "product": "P", "product_base_version": "1", "product_fix_version": "2"
    }
    vuln = Vulnerability(**data)
    assert vuln.cve_id == []