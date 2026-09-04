"""収集対象タイプ(config/sources.yaml の type)とcollectorクラスの対応表。

各collector実装が依存する外部ライブラリ(feedparser等)が未インストールでも、
実際にそのtypeを使うまではImportErrorを起こさないよう遅延importにしている。
"""

_REGISTRY_LOADERS = {}


def _load_rss():
    from collectors.rss_collector import RssCollector
    return RssCollector


def _load_kev():
    from collectors.kev_collector import KevCollector
    return KevCollector


def _load_nvd():
    from collectors.nvd_collector import NvdCollector
    return NvdCollector


def _load_github():
    from collectors.github_advisory_collector import GithubAdvisoryCollector
    return GithubAdvisoryCollector


_REGISTRY_LOADERS = {
    "rss": _load_rss,
    "kev_json": _load_kev,
    "nvd_api": _load_nvd,
    "github_advisory_api": _load_github,
}


def build_collector(source_conf: dict):
    loader = _REGISTRY_LOADERS.get(source_conf["type"])
    if loader is None:
        raise ValueError(f"unknown collector type: {source_conf['type']}")
    cls = loader()
    return cls(source_conf)