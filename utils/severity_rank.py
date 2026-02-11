def severity_rank(severity):
    cvss_v3_1_matrix = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Unknown": 0
    }
    return cvss_v3_1_matrix[severity]