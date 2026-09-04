"""テキストからCVE番号を抽出する。"""
import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_ids(text: str) -> list:
    if not text:
        return []
    found = {m.upper() for m in CVE_PATTERN.findall(text)}
    return sorted(found)


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,})\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_iocs(text: str) -> list:
    """簡易IOC抽出。あくまでRSSサマリ等の平文テキストからの抽出であり、
    公式アドバイザリ本体の詳細IOCについては source_url を参照する前提。
    戻り値: [(ioc_type, ioc_value), ...]
    """
    if not text:
        return []
    iocs = []
    for ip in set(IP_PATTERN.findall(text)):
        iocs.append(("ip", ip))
    for h in set(SHA256_PATTERN.findall(text)):
        iocs.append(("hash_sha256", h))
    for h in set(MD5_PATTERN.findall(text)):
        iocs.append(("hash_md5", h))
    return iocs