import pytest
from utils.format_date import format_date


# ==========================================================
#                   Valid Date Parsing
# ==========================================================

@pytest.mark.parametrize(
    "input_date, expected",
    [
        ("15 January 2024", "2024-01-15"),
        ("6 Nov 2025", "2025-11-06"),
        ("2024-01-15", "2024-01-15"),
        ("January 15, 2024", "2024-01-15"),
        (" 15 January 2024 ", "2024-01-15"),         # whitespace trimming
    ],
)
def test_format_date_valid_inputs(input_date, expected):
    # -------- Arrange --------
    date_str = input_date

    # -------- Act --------
    result = format_date(date_str)

    # -------- Assert --------
    assert result == expected


# ==========================================================
#                   Invalid Inputs
# ==========================================================

@pytest.mark.parametrize(
    "input_date",
    [
        None,
        "",
        123,
        [],
        {},
    ],
)
def test_format_date_invalid_inputs_return_none(input_date):
    # -------- Arrange --------
    date_str = input_date

    # -------- Act --------
    result = format_date(date_str)

    # -------- Assert --------
    assert result is None


# ==========================================================
#                   Unparseable Dates
# ==========================================================

@pytest.mark.parametrize(
    "input_date",
    [
        "not a date",
        "abcdefg",
        "32 January 2024",   # invalid day
        "Febtember 12 2023" # invalid month
    ],
)
def test_format_date_unparseable_dates_return_none(input_date):
    # -------- Arrange --------
    date_str = input_date

    # -------- Act --------
    result = format_date(date_str)

    # -------- Assert --------
    assert result is None