"""重要度(Critical/High/Medium/Low)判定。

Japan Risk Scoreとは独立に、CVSS・KEV掲載・実世界での悪用状況から
「世界的にどれだけ深刻か」を判定する。日本への影響度は別途
japan_relevance_score を参照すること。
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import (
    CVSS_CRITICAL_THRESHOLD,
    CVSS_HIGH_THRESHOLD,
    CVSS_MEDIUM_THRESHOLD,
)


def determine_severity(cvss: float = None, in_kev: bool = False,
                        is_ransomware_or_apt: bool = False) -> str:
    if in_kev:
        # KEV掲載(=悪用実績あり)は最低でもHigh扱い
        base = "High"
    else:
        base = None

    if cvss is not None:
        if cvss >= CVSS_CRITICAL_THRESHOLD:
            cvss_severity = "Critical"
        elif cvss >= CVSS_HIGH_THRESHOLD:
            cvss_severity = "High"
        elif cvss >= CVSS_MEDIUM_THRESHOLD:
            cvss_severity = "Medium"
        else:
            cvss_severity = "Low"
    else:
        cvss_severity = None

    candidates = [c for c in [base, cvss_severity] if c]
    if not candidates:
        result = "Medium" if is_ransomware_or_apt else "Low"
    else:
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        result = max(candidates, key=lambda c: order[c])

    if is_ransomware_or_apt and order_rank(result) < order_rank("High"):
        result = "High"

    return result


def order_rank(sev: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(sev, 0)