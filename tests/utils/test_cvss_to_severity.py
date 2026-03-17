import pytest
from utils.cvss_to_severity import cvss_to_severity


# ==========================================================
#                   CVSS v2 Severity Mapping
# ==========================================================

@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (10.0, "High"),
    ],
)
def test_cvss_v2_severity_mapping(score, expected):
    # -------- Arrange --------
    version = 2.0

    # -------- Act --------
    result = cvss_to_severity(score, version)

    # -------- Assert --------
    assert result == expected


# ==========================================================
#                   CVSS v3+ Severity Mapping
# ==========================================================

@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_cvss_v3_severity_mapping(score, expected):
    # -------- Arrange --------
    version = 3.1

    # -------- Act --------
    result = cvss_to_severity(score, version)

    # -------- Assert --------
    assert result == expected