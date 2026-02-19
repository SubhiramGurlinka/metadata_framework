import pytest
from unittest.mock import Mock, patch
from bs4 import BeautifulSoup
from strategies.vendor.oracle import OracleVendorStrategy


# ==========================================================
#                   format_date()
# ==========================================================

def test_format_date_converts_valid_date_to_iso_format():
    #  Arrange 
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    result = strategy.format_date("2024-January-15")

    #  Assert 
    assert result == "2024-01-15"


def test_format_date_raises_value_error_for_invalid_format():
    #  Arrange 
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError):
        strategy.format_date("15-01-2024")


# ==========================================================
#                   latest_cpu_url()
# ==========================================================

# SUCCESS CASE
@patch("strategies.vendor.oracle.get_soup")
def test_latest_cpu_url_returns_correct_url_and_source_id(mock_get_soup):
    #  Arrange 
    html = """
    <table>
        <tbody>
            <tr>
                <td>
                    <a href="/security-alerts/cpujan2026.html">
                        Critical Patch Update - January 2026
                    </a>
                </td>
            </tr>
            <tr>
                <td>
                    <a href="/security-alerts/cpuoct2025.html">
                        Critical Patch Update - October 2025
                    </a>
                </td>
            </tr>
        </tbody>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    url, source_id = strategy.latest_cpu_url("http://base-url")

    #  Assert 
    assert source_id == "cpujan2026"
    assert url == "http://base-url/cpujan2026.html"


# NO TABLE PRESENT
@patch("strategies.vendor.oracle.get_soup")
def test_latest_cpu_url_raises_when_table_missing(mock_get_soup):
    #  Arrange 
    html = "<html><body><p>No table here</p></body></html>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="CPU table not found"):
        strategy.latest_cpu_url("http://base-url")


# TABLE EXISTS BUT NO LINK
@patch("strategies.vendor.oracle.get_soup")
def test_latest_cpu_url_raises_when_link_missing(mock_get_soup):
    #  Arrange 
    html = """
    <table>
        <tr>
            <td>No anchor tag here</td>
        </tr>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="CPU link not found"):
        strategy.latest_cpu_url("http://base-url")


# NETWORK FAILURE
@patch("strategies.vendor.oracle.get_soup")
def test_latest_cpu_url_raises_on_network_failure(mock_get_soup):
    #  Arrange 
    mock_get_soup.return_value = Exception("Network error")

    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(RuntimeError, match="Failed to fetch base page"):
        strategy.latest_cpu_url("http://base-url")


# MULTIPLE LINKS — ENSURE FIRST IS USED
@patch("strategies.vendor.oracle.get_soup")
def test_latest_cpu_url_uses_first_link_when_multiple_exist(mock_get_soup):
    #  Arrange 
    html = """
    <table>
        <tbody>
            <tr>
                <td><a href="/security-alerts/cpujan2026.html">Jan</a></td>
            </tr>
            <tr>
                <td><a href="/security-alerts/cpuoct2025.html">Oct</a></td>
            </tr>
        </tbody>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    url, source_id = strategy.latest_cpu_url("http://base-url")

    #  Assert 
    assert source_id == "cpujan2026"
    assert url == "http://base-url/cpujan2026.html"



# ==========================================================
#               get_release_date()
# ==========================================================

# SUCCESS CASE
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_returns_formatted_date(mock_get_soup):
    #  Arrange 
    html = """
    <h3>Modification History</h3>
    <table>
        <tbody>
            <tr>
                <td>Irrelevant Row</td>
            </tr>
            <tr>
                <td>Irrelevant Row</td>
            </tr>
        </tbody>
        <tbody>
            <tr>
                <td>2026-January-15</td>
                <td>Some DataS</td>
            </tr>
        </tbody>
    </table>
    """
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act 
    formatted_date = strategy.get_release_date("http://cpu-url")

    #  Assert 
    assert formatted_date == "2026-01-15"


# get_soup RETURNS EXCEPTION
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_raises_on_get_soup_exception(mock_get_soup):
    #  Arrange 
    mock_get_soup.return_value = Exception("Network Error")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(RuntimeError, match="Failed to fetch CPU page"):
        strategy.get_release_date("http://cpu-url")


# MISSING MODIFICATION HISTORY <h3>
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_raises_when_h3_missing(mock_get_soup):
    #  Arrange 
    html = "<html><body><p>No h3 here</p></body></html>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="Modification history section not found"):
        strategy.get_release_date("http://cpu-url")

# MISSING TABLE AFTER <h3>
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_raises_when_table_missing(mock_get_soup):
    #  Arrange 
    html = "<h3>Modification History</h3><p>No table here</p>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="Modification history table not found"):
        strategy.get_release_date("http://cpu-url")

# NO TBODY IN TABLE
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_raises_when_tbodies_missing(mock_get_soup):
    #  Arrange 
    html = "<h3>Modification History</h3><table></table>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="No table body found"):
        strategy.get_release_date("http://cpu-url")

# NO ROWS IN LAST TBODY
@patch("strategies.vendor.oracle.get_soup")
def test_get_release_date_raises_when_last_tbody_has_no_rows(mock_get_soup):
    #  Arrange 
    html = """
    <h3>Modification History</h3>
    <table>
        <tbody></tbody>
        <tbody>
            <tr><td>Dummy Data<td><tr>
        </tbody>
        <tbody></tbody>
    </table>
    """
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    strategy = OracleVendorStrategy(parser=None, software_cfg={}, vendor_cfg={})

    #  Act & Assert 
    with pytest.raises(ValueError, match="No rows found in modification table"):
        strategy.get_release_date("http://cpu-url")


# ==========================================================
# process()
# ==========================================================

import pytest
from unittest.mock import Mock
from models import Vulnerability
from strategies.vendor.oracle import OracleVendorStrategy


# ==========================================================
# SUCCESS: process returns parser result and builds context
# ==========================================================
def test_process_success_returns_parser_result():
    # ----------------- Arrange -----------------
    mock_parser = Mock()

    expected_vulnerability = Vulnerability(
        vendor="Oracle",
        cve_id=["CVE-2026-1234"],
        source_id="cpujan2026",
        severity="Critical",
        product_base_version="19",
        product="Oracle DB",
        product_fix_version="19.11",
        published_date="2026-02-15"
    )

    mock_parser.parse.return_value = expected_vulnerability

    strategy = OracleVendorStrategy(
        parser=mock_parser,
        software_cfg={"display_name": "Oracle DB"},
        vendor_cfg={}
    )

    strategy.get_url = Mock(return_value="http://base-url")
    strategy.latest_cpu_url = Mock(return_value=("http://cpu-url", "cpujan2026"))
    strategy.get_release_date = Mock(return_value="2026-02-15")

    # ----------------- Act -----------------
    result = strategy.process("Oracle DB", "19", "19.11")

    # ----------------- Assert -----------------
    assert result == expected_vulnerability

    strategy.get_url.assert_called_once_with("19")
    strategy.latest_cpu_url.assert_called_once_with("http://base-url")
    strategy.get_release_date.assert_called_once_with("http://cpu-url")

    mock_parser.parse.assert_called_once()

    called_url, context = mock_parser.parse.call_args[0]

    assert called_url == "http://cpu-url"
    assert context == {
        "url": "http://cpu-url",
        "product": "Oracle DB",
        "source_id": "cpujan2026",
        "base_version": "19",
        "release_date": "2026-02-15",
        "product_fix_version": "19.11",
        "sw_display_name": "Oracle DB"
    }


# ==========================================================
# FAILURE: get_url raises exception
# ==========================================================
def test_process_raises_if_get_url_fails():
    mock_parser = Mock()

    strategy = OracleVendorStrategy(
        parser=mock_parser,
        software_cfg={},
        vendor_cfg={}
    )

    strategy.get_url = Mock(side_effect=ValueError("Invalid base version"))

    with pytest.raises(ValueError, match="Invalid base version"):
        strategy.process("Oracle DB", "19c", "19c.1")

    mock_parser.parse.assert_not_called()


# ==========================================================
# FAILURE: latest_cpu_url raises exception
# ==========================================================
def test_process_raises_if_latest_cpu_url_fails():
    mock_parser = Mock()

    strategy = OracleVendorStrategy(
        parser=mock_parser,
        software_cfg={},
        vendor_cfg={}
    )

    strategy.get_url = Mock(return_value="http://base-url")
    strategy.latest_cpu_url = Mock(side_effect=ValueError("CPU table not found"))

    with pytest.raises(ValueError, match="CPU table not found"):
        strategy.process("Oracle DB", "19c", "19c.1")

    mock_parser.parse.assert_not_called()


# ==========================================================
# FAILURE: get_release_date raises exception
# ==========================================================
def test_process_raises_if_get_release_date_fails():
    mock_parser = Mock()

    strategy = OracleVendorStrategy(
        parser=mock_parser,
        software_cfg={},
        vendor_cfg={}
    )

    strategy.get_url = Mock(return_value="http://base-url")
    strategy.latest_cpu_url = Mock(return_value=("http://cpu-url", "cpujan2026"))
    strategy.get_release_date = Mock(side_effect=RuntimeError("Failed to fetch CPU page"))

    with pytest.raises(RuntimeError, match="Failed to fetch CPU page"):
        strategy.process("Oracle DB", "19c", "19c.1")

    mock_parser.parse.assert_not_called()

