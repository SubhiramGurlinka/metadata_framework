import pytest
from bs4 import BeautifulSoup
from unittest.mock import patch
from models import Vulnerability
from strategies.parsers.oracle_cpu_parser import OracleCpuParser


# ==========================================================
# Helper
# ==========================================================

def build_context(product="Oracle DB", base_version="19"):
    return {
        "product": product,
        "base_version": base_version,
        "release_date": "2026-01-15",
        "source_id": "cpujan2026",
        "product_fix_version": "19.20",
        "sw_display_name": "Oracle Database"
    }


# ==========================================================
# row_contains_product()
# ==========================================================

def test_row_contains_product_true():
    parser = OracleCpuParser()

    html = """
    <tr>
        <td>Oracle DB</td>
    </tr>
    """
    row = BeautifulSoup(html, "html.parser").find("tr")

    assert parser.row_contains_product(row, "oracle db") is True


def test_row_contains_product_false():
    parser = OracleCpuParser()

    html = """
    <tr>
        <td>MySQL</td>
    </tr>
    """
    row = BeautifulSoup(html, "html.parser").find("tr")

    assert parser.row_contains_product(row, "oracle db") is False


# ==========================================================
# cleanup()
# ==========================================================

def test_cleanup_returns_matching_version():
    parser = OracleCpuParser()

    result = parser.cleanup(
        "oracle db",
        "oracle db: 19.0; mysql: 8.0"
    )

    assert result == "19.0"


def test_cleanup_returns_original_when_no_semicolon():
    parser = OracleCpuParser()

    result = parser.cleanup("oracle db", "19.0")

    assert result == "19.0"


def test_cleanup_raises_for_invalid_format():
    parser = OracleCpuParser()

    with pytest.raises(ValueError, match="Invalid format"):
        parser.cleanup("oracle db", "oracle db 19.0; mysql: 8.0")


# ==========================================================
# parse() — SUCCESS CASE
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.cvss_to_severity")
@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_success_non_oracle_db(mock_get_soup, mock_cvss):

    html = """
    <table>
        <tbody>
            <tr><td>Index</td></tr>
        </tbody>
    </table>

    <table>
        <tbody>
            <tr>
                <th>CVE-2026-0001</th>
                <td>Oracle DB</td>
                <td></td>
                <td></td>
                <td></td>
                <td>9.8</td>
                <td>19</td>
                <td>19</td>
            </tr>
        </tbody>
    </table>
    """


    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    mock_cvss.return_value = "Critical"

    parser = OracleCpuParser()
    context = build_context()

    result = parser.parse("http://cpu-url", context)

    assert isinstance(result, Vulnerability)
    assert result.cve_id == ["CVE-2026-0001"]
    assert result.severity == "Critical"
    assert result.vendor == "Oracle"
    assert result.product_base_version == "19"
    assert result.product_fix_version == "19.20"
    assert result.source_id == "cpujan2026"
    assert result.published_date == "2026-01-15"

    mock_cvss.assert_called_once_with(9.8, 3.1)


# ==========================================================
# parse() — MULTIPLE CVEs, highest chosen
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.cvss_to_severity")
@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_selects_highest_cvss(mock_get_soup, mock_cvss):

    html = """
    <table>
        <tbody>
            <tr><td>Index</td></tr>
        </tbody>
    </table>

    <table>
        <tbody>
            <tr>
                <th>CVE-1234-56789</th>
                <td>Oracle DB</td>
                <td> </td>
                <td> </td>
                <td> </td>
                <td>5.0</td>
                <td>19</td>
                <td>19</td>
            </tr>
            <tr>
                <th>CVE-1234-5678</th>
                <td>Oracle DB</td>
                <td> </td>
                <td> </td>
                <td> </td>
                <td>9.1</td>
                <td>19</td>
                <td>19</td>
            </tr>
        </tbody>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    mock_cvss.return_value = "Critical"

    parser = OracleCpuParser()
    context = build_context()

    result = parser.parse("http://cpu-url", context)

    assert sorted(result.cve_id) == ["CVE-1234-5678", "CVE-1234-56789"]
    mock_cvss.assert_called_once_with(9.1, 3.1)


# ==========================================================
# parse() — Oracle Database special branch
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.cvss_to_severity")
@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_oracle_database_branch(mock_get_soup, mock_cvss):

    html = """
    <h4>oracle database Risk Matrix</h4>
    <table>
        <tbody>
            <tr>
                <th>CVE-1234-123456</th>
                <td></td><td></td><td></td>
                <td>7.5</td>
                <td>19</td>
                <td>19</td>
            </tr>
        </tbody>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")
    mock_cvss.return_value = "High"

    parser = OracleCpuParser()
    context = build_context(product="Oracle Database")

    result = parser.parse("http://cpu-url", context)

    assert result.cve_id == ["CVE-1234-123456"]
    assert result.severity == "High"


# ==========================================================
# parse() — No matching version
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_returns_empty_cve_list_when_no_match(mock_get_soup):

    html = """
    <table>
        <tbody>
            <tr><td>Index</td></tr>
        </tbody>
    </table>

    <table>
        <tbody>
            <tr>
                <th>CVE-1</th>
                <td>Oracle DB</td>
                <td></td><td></td>
                <td>8.0</td>
                <td>21</td>
                <td>21</td>
            </tr>
        </tbody>
    </table>
    """

    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    parser = OracleCpuParser()
    context = build_context(base_version="19")

    result = parser.parse("http://cpu-url", context)

    # assert result.cve_id == []
    assert isinstance(result, Vulnerability)
    assert result.cve_id == ['']
    assert result.severity == ""


# ==========================================================
# parse() — get_soup returns Exception
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_returns_none_when_soup_fails(mock_get_soup):

    mock_get_soup.return_value = Exception("Network error")

    parser = OracleCpuParser()
    context = build_context()

    result = parser.parse("http://cpu-url", context)

    assert result is None


# ==========================================================
# parse() — Missing tbody
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_returns_none_when_no_tbody(mock_get_soup):

    html = "<html></html>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    parser = OracleCpuParser()
    context = build_context()

    result = parser.parse("http://cpu-url", context)

    assert result is None


# ==========================================================
# parse() — Missing Risk Matrix section
# ==========================================================

@patch("strategies.parsers.oracle_cpu_parser.get_soup")
def test_parse_returns_none_when_risk_matrix_missing(mock_get_soup):

    html = "<html></html>"
    mock_get_soup.return_value = BeautifulSoup(html, "html.parser")

    parser = OracleCpuParser()
    context = build_context(product="Oracle Database")

    result = parser.parse("http://cpu-url", context)

    assert result is None
