"""グローバル設定・しきい値・キーワード辞書。

このファイルの値を調整するだけで、Japan Risk Scoreの重み付けや
ステータス遷移の日数しきい値、業種分類キーワードなどを変更できる。
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = DATA_DIR / "threat_intel.db"
SOURCES_YAML = BASE_DIR / "config" / "sources.yaml"
DAILY_REPORT_PATH = BASE_DIR / "daily_report.md"

# --- Japan Risk Score 加点表 (analyzers/japan_relevance.py で使用) ---
JAPAN_RISK_WEIGHTS = {
    "confirmed_victim_in_japan": 40,   # 日本企業/組織で実被害確認
    "explicit_japan_target": 30,       # 日本を明示的に標的
    "widely_used_in_japan": 20,        # 日本で広く利用されている製品
    "exploited_in_wild": 20,           # 悪用確認済み脆弱性
    "kev_listed": 15,                  # CISA KEV掲載
    "ransomware_or_apt": 10,           # ランサムウェア/APT関連
    "japanese_phishing": 15,           # 日本語フィッシング確認
    "japan_ip_observed": 10,           # 日本IPへの攻撃観測
    "low_trust_source_only": -20,      # 信頼度の低い情報のみ
}
JAPAN_RISK_SCORE_MIN = 0
JAPAN_RISK_SCORE_MAX = 100

# 日本で広く利用されている代表的な製品/ベンダー(判定キーワード, 適宜追加)
WIDELY_USED_IN_JAPAN_PRODUCTS = [
    "windows", "microsoft 365", "active directory", "exchange server",
    "fortigate", "fortios", "ivanti", "citrix", "vmware esxi",
    "cisco ios", "pulse secure", "sonicwall", "trend micro",
    "salesforce", "sap", "oracle", "adobe", "chrome", "android",
    "ios", "confluence", "jira", "movable type", "wordpress",
]

# 日本語/日本関連判定のためのキーワード
JAPAN_KEYWORDS_JA = ["日本", "国内", "邦人", "自治体", "総務省", "経産省", "警察庁"]
JAPAN_KEYWORDS_EN = ["japan", "japanese", "tokyo", "osaka", "jpcert", " jp "]

# 業種分類キーワード(sector判定, config内で拡張可能)
SECTOR_KEYWORDS = {
    "金融": ["bank", "銀行", "証券", "保険", "financial", "fintech"],
    "医療": ["hospital", "病院", "医療", "healthcare", "clinic"],
    "物流": ["logistics", "物流", "運送", "shipping", "supply chain"],
    "通信": ["telecom", "通信", "carrier", "isp"],
    "交通": ["railway", "鉄道", "航空", "airline", "transport"],
    "重要インフラ": ["infrastructure", "インフラ", "電力", "power grid", "water utility", "energy"],
    "自治体": ["municipal", "自治体", "県庁", "市役所", "government"],
    "製造": ["manufacturing", "製造", "工場", "factory"],
    "小売": ["retail", "小売", "ec", "eコマース"],
}

# --- 重要度(severity)判定しきい値 ---
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

# --- ステータス遷移(analyzers/status.py) ---
STATUS_NEW = "NEW"
STATUS_ACTIVE = "ACTIVE"
STATUS_ESCALATED = "ESCALATED"
STATUS_MITIGATED = "MITIGATED"
STATUS_CLOSED = "CLOSED"

# 最終更新からこの日数、動きが無ければ CLOSED 候補とする
DAYS_UNTIL_CLOSED_CANDIDATE = 21
# 新規登録からこの日数以内は NEW 扱い
DAYS_AS_NEW = 3

# --- 重複排除(analyzers/dedup.py) ---
DEDUP_TITLE_SIMILARITY_THRESHOLD = 0.8
DEDUP_DATE_WINDOW_DAYS = 3

# --- カテゴリ分類キーワード(update.pyの重要度判定 / daily_reportの分類の両方で使用) ---
CATEGORY_KEYWORDS = {
    "ransomware": ["ransomware", "ランサムウェア", "ランサム"],
    "apt": [" apt", "apt", "nation-state", "国家", "標的型"],
    "ddos": ["ddos", "dos攻撃", "サービス拒否", "denial of service", "d/dos"],
}

# --- daily_report.md 生成(reporting/daily_report.py で使用) ---
JAPAN_VICTIM_REASON_MARKERS = ["被害を示す語句", "実被害"]  # japan_relevance_reasonsに含まれると実被害扱い
REPORT_TOP_N_PER_SECTION = 20

# --- 収集時の共通設定 ---
HTTP_TIMEOUT_SECONDS = 20
USER_AGENT = "cyber-threat-japan-collector/0.1 (blue-team threat intel; public sources only)"