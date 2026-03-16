# format_date.py

from dateutil import parser

def format_date(date: str):
    """
    Convert various date formats to ISO format (YYYY-MM-DD).

    Returns:
        str: formatted date
        None: if parsing fails
    """
    if not date or not isinstance(date, str):
        return None

    try:
        dt = parser.parse(date.strip(), fuzzy=True)
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError, OverflowError):
        return None