def cvss_to_severity(score: float, version: float) -> str:
    if version == 2.0:
        if score <= 3.9: return "Low"
        if score <= 6.9: return "Medium"
        return "High"
    
    else:
        if score == 0.0: return "None"
        if score <= 3.9: return "Low"
        if score <= 6.9: return "Medium"
        if score <= 8.9: return "High"
        return "Critical"