# severity_rank.py

CVSS_RANK_MAP = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "None": 0
}

def severity_rank(severity):
    return CVSS_RANK_MAP.get(severity, 0)