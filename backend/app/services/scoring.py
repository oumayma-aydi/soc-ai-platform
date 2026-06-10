def compute_severity(ioc_count: int, suspicious_actions: int) -> int:
    """
    Simple scoring initial (tu amélioreras avec IA plus tard)
    """

    score = 1

    # plus d'IOCs = plus suspect
    if ioc_count > 3:
        score += 3
    elif ioc_count > 1:
        score += 2

    # activités suspectes
    if suspicious_actions > 5:
        score += 4
    elif suspicious_actions > 2:
        score += 2

    # clamp score 1-10
    return max(1, min(score, 10))