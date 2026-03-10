import pytest
from unittest.mock import patch, AsyncMock

from strategies.parsers.ibm_db2_parser import IBMDB2FixListParser
from models import Vulnerability

@patch("strategies.parsers.ibm_db2_parser.get_response_text")
@patch("strategies.parsers.ibm_db2_parser.CVESeverityService")
@patch.object(IBMDB2FixListParser, "get_source_id_and_release_date")
def test_parse_extracts_cves(
    mock_metadata,
    mock_severity_service,  
    mock_get_response
):

    # Mock metadata method
    mock_metadata.return_value = (
        "12345",                # source_id
        "10.Jan.2024",          # release_date
        "http://fake-cve-page"  # cve page
    )

    # Mock CVE page
    cve_page = """
    <html>
        <table class="bx--data-table">
            <thead>
                <tr>
                    <th>Db2 12.1.2 Fix Pack m2fp0</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>CVE-2024-1111</td>
                </tr>
                <tr>
                    <td>CVE-2024-2222</td>
                </tr>
            </tbody>
        </table>
    </html>
    """

    mock_get_response.return_value = cve_page

    mock_service = mock_severity_service.return_value
    mock_service.get_multiple_severities = AsyncMock(
        return_value={
            "CVE-2024-1111": "Low",
            "CVE-2024-2222": "Critical"
        }
    )

    parser = IBMDB2FixListParser()

    context = {
        "product": "IBM Db2",
        "base_version": "12.1",
        "product_fix_version": "12.1.2",
        "date_url": "http://fake-url"
    }

    result = parser.parse("", context)

    assert isinstance(result, Vulnerability)

    assert result.cve_id == ["CVE-2024-1111", "CVE-2024-2222"]
    assert result.severity == "Critical"
    assert result.source_id == ["12345"]
    assert result.published_date == "2024-01-10"