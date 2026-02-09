from datetime import datetime, date
from dateutil import parser
import re

def normalize_date_to_iso(date_input, dayfirst: bool | None = None) -> str:
    """
    Normalize various date inputs to ISO format (YYYY-MM-DD).

    Accepts:
      - string dates in many formats
      - datetime.datetime
      - datetime.date

    Raises:
      - ValueError for ambiguous numeric dates if dayfirst is None
    """

    # Case 1: already a datetime/date object
    if isinstance(date_input, (datetime, date)):
        return date_input.strftime("%Y-%m-%d")

    # Case 2: must be a string from here
    if not isinstance(date_input, str):
        raise TypeError("date_input must be str, datetime, or date")

    date_input = date_input.strip()

    # Already ISO
    try:
        dt = datetime.strptime(date_input, "%Y-%m-%d")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass

    # Detect ambiguous numeric format
    match = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})$", date_input)
    if match:
        part1, part2, _ = match.groups()
        if int(part1) <= 12 and int(part2) <= 12 and dayfirst is None:
            raise ValueError(
                f"Ambiguous date '{date_input}'. "
                "Specify dayfirst=True (DD/MM) or dayfirst=False (MM/DD)."
            )

    # Parse flexibly
    dt = parser.parse(date_input, dayfirst=dayfirst if dayfirst is not None else False)
    return dt.strftime("%Y-%m-%d")
