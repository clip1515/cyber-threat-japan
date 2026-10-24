"""出典が公開したIOC(config/reported_iocs.yaml)の検証と正規化。

RSS本文からの自動抽出(parsers/cve_extractor.extract_iocs)とは別物で、人が出典の本文を確認して
登録する。登録するのは出典の記載(出典URL・種別・観測期間・確認日・信頼性・用途)までで、
遮断や攻撃者の特定には使わない。

読み込み(load_document)では、YAMLの重複キーとマージキー(<<)をどの階層でも拒否する。PyYAML の safe_load は
重複キーを黙って後の値で上書きするため、`iocs:` を2回書くと後の空一覧が正当な「登録なし」に見えてしまう。

検証(型・形式・範囲・制御文字・アドレスの種別・重複・ファイル全体の形)は、DBに書く前にすべての項目について
Python 側で行う。DBのCHECK制約(database/schema.sql)が保証するのは NOT NULL・列挙値・信頼度の値の範囲・
https で始まること・日付の書式・(ioc_type, ioc_value, source_url) の一意性だけで、型(SQLiteの型親和性で 1 と
'1' が相互に変換される)・URLの形式・アドレスの種別・日付の範囲・文字数・制御文字・重複キーは保証しない。
"""
import ipaddress
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

import yaml

TYPES = {"ip"}
# 外部の観測情報は公式文書とは別の出典(別の行)として扱う。同じIPでも出典ごとに観測期間・確認日を持つ。
SOURCE_KINDS = {"official_advisory", "external_observation"}
CONFIDENCE = {"reported", "corroborated"}  # 出典が報告している / 複数の出典で裏付けあり
USAGE = {"reference", "detection"}         # 参照・照合のみ。遮断用の値は受け付けない
TRUST_LEVELS = {1, 2, 3}                   # config/sources.yaml の trust_level と同じ尺度
FIELDS = {"ioc_type", "ioc_value", "source_url", "source_name", "source_kind", "source_trust_level",
          "source_published_at", "observed_from", "observed_to", "source_checked_at", "confidence", "usage",
          "context"}
REQUIRED = {"ioc_type", "ioc_value", "source_url", "source_name", "source_kind", "source_trust_level",
            "source_checked_at", "confidence", "usage"}
DATE_FIELDS = ("source_published_at", "observed_from", "observed_to", "source_checked_at")
MAX_LEN = {"source_url": 2048, "source_name": 200, "context": 500, "ioc_value": 100}
EARLIEST = date(2000, 1, 1)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# IPv4 を埋め込んだ IPv6 表記。同じ IPv4 を別の表記で登録できてしまう(重複判定をすり抜ける)ため受け付けない。
IPV4_EMBEDDING_NETWORKS = (ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("64:ff9b::/96"))


class DuplicateKeyError(yaml.YAMLError):
    """同じ辞書の中にキーが2回以上書かれている、またはマージキー(<<)が使われている。"""


class _StrictLoader(yaml.SafeLoader):
    """safe_load と同じ型だけを作り、重複キーとマージキーをどの階層でも拒否する。"""


def _construct_strict_mapping(loader, node):
    seen = set()
    for key_node, _ in node.value:
        line = key_node.start_mark.line + 1
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise DuplicateKeyError(f"マージキー(<<)は使えません({line}行目)")
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in seen
        except TypeError:
            raise DuplicateKeyError(f"辞書のキーに使えない値があります({line}行目)") from None
        if duplicate:
            raise DuplicateKeyError(f"重複したキーがあります({line}行目)")  # キー名・値はメッセージに含めない
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_strict_mapping)


def load_document(text):
    """config/reported_iocs.yaml の本文を読み込む。重複キー・マージキーは DuplicateKeyError、
    それ以外の構文エラーは yaml.YAMLError を送出する。"""
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506  SafeLoader の派生(任意のオブジェクトは作らない)


def normalize_ip(value) -> str:
    """表記ゆれ(前後の空白、[.] による無害化表記)を正規化し、global unicast として扱えるアドレスだけを返す。

    受け付ける条件(すべてを満たすこと):
    - ipaddress で IPv4 / IPv6 として解釈できる
    - is_global が真(IANA の special-purpose 登録簿で globally reachable とされる範囲。判定は Python の
      ipaddress モジュールの版に依存する)
    - マルチキャストではない(224.0.0.0/4、ff00::/8。is_global が真になるものがあるため別に確認する)
    - IPv6 はスコープID(%eth0 など)を持たない
    - IPv4 を埋め込んだ IPv6 表記(::ffff:0:0/96、64:ff9b::/96)ではない(IPv4 の表記で登録する)
    """
    if type(value) is not str:
        raise ValueError("ioc_value は文字列で書いてください")
    try:
        addr = ipaddress.ip_address(value.strip().replace("[.]", ".").replace("[:]", ":"))
    except ValueError:
        raise ValueError("ioc_value がIPアドレスとして解釈できません") from None  # 入力値はエラー文に含めない
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.scope_id is not None:
            raise ValueError("ioc_value にスコープID付きのIPv6アドレスは使えません")
        if any(addr in net for net in IPV4_EMBEDDING_NETWORKS):
            raise ValueError("ioc_value のIPv4を埋め込んだIPv6表記は使わず、IPv4で書いてください")
    if addr.is_multicast:
        raise ValueError("ioc_value にマルチキャストアドレスは使えません")
    if not addr.is_global:
        raise ValueError("ioc_value がグローバルアドレスではありません")
    return str(addr)


def _text(e, name, optional=False):
    value = e.get(name)
    if value is None and optional:
        return None
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} は空でない文字列で書いてください")
    if CONTROL.search(value):
        raise ValueError(f"{name} に改行・制御文字を含めないでください")
    if len(value) > MAX_LEN.get(name, 100):
        raise ValueError(f"{name} が長すぎます(最大 {MAX_LEN.get(name, 100)} 文字)")
    return value.strip()


def _choice(e, name, allowed):
    value = _text(e, name)
    if value not in allowed:
        raise ValueError(f"{name} は {sorted(allowed)} のいずれかです")
    return value


def _url(e):
    value = _text(e, "source_url")
    try:
        parts = urlsplit(value)
        port_ok = parts.port is None or 0 < parts.port < 65536
    except ValueError:
        port_ok = False
    if (not port_ok or parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or any(ch.isspace() for ch in value)):
        raise ValueError("source_url は認証情報や空白を含まない https:// のURLにしてください")
    return value


def _date(e, name, today):
    value = e.get(name)
    if value is None:
        return None
    if type(value) is date:  # YAML の日付(datetime は時刻を持つため受け付けない)
        d = value
    elif type(value) is str and ISO_DATE.fullmatch(value):
        try:
            d = date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"{name} は存在する日付(YYYY-MM-DD)で書いてください") from None
    else:
        raise ValueError(f"{name} は YYYY-MM-DD の日付で書いてください")
    if not EARLIEST <= d <= today + timedelta(days=1):
        raise ValueError(f"{name} が範囲外です({EARLIEST.isoformat()} 〜 今日)")
    return d.isoformat()


def validate_entries(entries, today=None):
    """(rows, errors) を返す。rows は DB へそのまま入れられる dict のリスト。

    エラー文には項目名と理由だけを書き、入力値そのものは含めない(ログや警告の偽装・漏えい防止)。
    """
    today = today or datetime.now(timezone.utc).date()
    rows, errors, seen = [], [], set()
    if type(entries) is not list:
        return [], ["iocs は一覧(リスト)で書いてください"]
    for i, e in enumerate(entries):
        try:
            if type(e) is not dict:
                raise ValueError("項目が辞書ではありません")
            if not all(type(k) is str for k in e):
                raise ValueError("項目名は文字列で書いてください")
            unknown, missing = set(e) - FIELDS, {k for k in REQUIRED if e.get(k) is None}
            if unknown or missing:
                raise ValueError(f"未知の項目 {sorted(unknown)} / 必須項目の欠落 {sorted(missing)}")
            row = {
                "ioc_type": _choice(e, "ioc_type", TYPES),
                "ioc_value": normalize_ip(_text(e, "ioc_value")),
                "source_url": _url(e),
                "source_name": _text(e, "source_name"),
                "source_kind": _choice(e, "source_kind", SOURCE_KINDS),
                "confidence": _choice(e, "confidence", CONFIDENCE),
                "usage": _choice(e, "usage", USAGE),
                "context": _text(e, "context", optional=True),
            }
            trust = e.get("source_trust_level")
            if type(trust) is not int or trust not in TRUST_LEVELS:
                raise ValueError("source_trust_level は整数の 1/2/3 のいずれかです")
            row["source_trust_level"] = trust
            for name in DATE_FIELDS:
                row[name] = _date(e, name, today)
            if row["observed_from"] and row["observed_to"] and row["observed_from"] > row["observed_to"]:
                raise ValueError("observed_from が observed_to より後です")
            key = (row["ioc_type"], row["ioc_value"], row["source_url"])
            if key in seen:
                raise ValueError("同じ出典の同じIOCが重複しています")
            seen.add(key)
            rows.append(row)
        except ValueError as ex:
            errors.append(f"iocs[{i}]: {ex}")
    return rows, errors


def parse_document(data, today=None):
    """YAMLを読み込んだ結果全体を検証する。最上位は `iocs` キーだけを持つ辞書でなければならない。

    明示的な `iocs: []` だけを「登録なし」として扱う。空ファイル・{}・null・false・型違いは拒否する
    (既存の登録を消さないため)。
    """
    if type(data) is not dict or set(data) != {"iocs"}:
        return [], ["ファイルの最上位は `iocs:` だけを持つ辞書にしてください(登録なしは `iocs: []`)"]
    return validate_entries(data["iocs"], today=today)
