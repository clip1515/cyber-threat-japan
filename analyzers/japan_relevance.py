"""Japan Risk Score (0-100) の計算。

単純なキーワード一致だけに頼らず、複数のシグナル(情報源の地域、
テキスト中の日本関連キーワード、広く使われる製品名、KEV掲載、
ランサムウェア/APT関連、フィッシング等)を組み合わせて加点する。

このスコアはあくまで一次スクリーニング用のヒューリスティックであり、
最終判断は必ず confirmed_facts / source_url を人間が確認すること
(README「誤検知の確認方法」を参照)。
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import (
    JAPAN_RISK_WEIGHTS,
    JAPAN_RISK_SCORE_MIN,
    JAPAN_RISK_SCORE_MAX,
    WIDELY_USED_IN_JAPAN_PRODUCTS,
    JAPAN_KEYWORDS_JA,
    JAPAN_KEYWORDS_EN,
)

VICTIM_WORDS = ["被害", "流出", "侵害", "breach", "compromised", "hacked", "victim", "attacked"]
RANSOMWARE_APT_WORDS = ["ransomware", "ランサムウェア", "ランサム", " apt", "apt", "nation-state", "国家"]
PHISHING_WORDS_JA = ["フィッシング", "なりすましメール"]


def analyze_japan_relevance(raw_text: str, source_region: str, source_trust_level: int,
                             extra: dict = None) -> tuple:
    """戻り値: (score:int, reasons:list[str])"""
    extra = extra or {}
    text_lower = (raw_text or "").lower()
    reasons = []
    score = 0

    has_jp_keyword = any(k in raw_text for k in JAPAN_KEYWORDS_JA) or \
        any(k in text_lower for k in JAPAN_KEYWORDS_EN)
    has_victim_word = any(w in raw_text or w in text_lower for w in VICTIM_WORDS)
    has_product = next((p for p in WIDELY_USED_IN_JAPAN_PRODUCTS if p in text_lower), None)
    is_ransom_apt = any(w in text_lower for w in RANSOMWARE_APT_WORDS)
    in_kev = bool(extra.get("in_kev"))
    exploited = in_kev or (extra.get("known_ransomware_use") not in (None, "Unknown", "unknown"))
    has_phishing_ja = any(w in raw_text for w in PHISHING_WORDS_JA)

    if source_region == "jp" and has_jp_keyword and has_victim_word:
        score += JAPAN_RISK_WEIGHTS["confirmed_victim_in_japan"]
        reasons.append("日本国内情報源+被害を示す語句を検出(要一次情報での裏取り)")

    if has_jp_keyword and source_region == "jp":
        score += JAPAN_RISK_WEIGHTS["explicit_japan_target"]
        reasons.append("日本関連キーワードを日本国内情報源で検出")
    elif has_jp_keyword:
        score += JAPAN_RISK_WEIGHTS["explicit_japan_target"] // 2
        reasons.append("海外情報源だが日本関連キーワードを検出")

    if has_product:
        score += JAPAN_RISK_WEIGHTS["widely_used_in_japan"]
        reasons.append(f"日本で広く利用される製品/ベンダーに言及: {has_product}")

    if exploited:
        score += JAPAN_RISK_WEIGHTS["exploited_in_wild"]
        reasons.append("悪用が確認されている脆弱性(KEV等)")

    if in_kev:
        score += JAPAN_RISK_WEIGHTS["kev_listed"]
        reasons.append("CISA KEVに掲載")

    if is_ransom_apt:
        score += JAPAN_RISK_WEIGHTS["ransomware_or_apt"]
        reasons.append("ランサムウェア/APT関連の語句を検出")

    if has_phishing_ja:
        score += JAPAN_RISK_WEIGHTS["japanese_phishing"]
        reasons.append("日本語フィッシングに関する記述を検出")

    if source_trust_level >= 3 and score == 0:
        score += JAPAN_RISK_WEIGHTS["low_trust_source_only"]
        reasons.append("信頼度の低い情報源のみで日本関連シグナルなし")

    score = max(JAPAN_RISK_SCORE_MIN, min(JAPAN_RISK_SCORE_MAX, score))
    return score, reasons