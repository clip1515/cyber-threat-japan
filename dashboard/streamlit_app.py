"""Streamlitダッシュボード本体。

SQLiteの現在の状態を読み取って表示するだけで、収集・解析処理は行わない
(それらは update.py の役割)。
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.append(str(Path(__file__).resolve().parent.parent))
from config.settings import DB_PATH
from database import db as dbmod

st.set_page_config(page_title="日本向けサイバー脅威監視ダッシュボード", layout="wide")


def load_incidents_df():
    if not DB_PATH.exists():
        return pd.DataFrame()
    with dbmod.connection() as conn:
        rows = dbmod.list_incidents(conn, limit=5000)
    df = pd.DataFrame([dict(r) for r in rows])
    if df.empty:
        return df
    for col in ["first_seen_at", "published_at", "last_updated_at", "created_at", "updated_at"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df


def load_iocs_df():
    with dbmod.connection() as conn:
        rows = conn.execute(
            "SELECT iocs.*, incidents.title AS incident_title FROM iocs "
            "JOIN incidents ON incidents.id = iocs.incident_id ORDER BY iocs.id DESC LIMIT 500"
        ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def load_cves_df():
    with dbmod.connection() as conn:
        rows = conn.execute("SELECT * FROM cves ORDER BY last_checked_at DESC LIMIT 500").fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def load_sources_df():
    with dbmod.connection() as conn:
        rows = conn.execute("SELECT * FROM sources ORDER BY trust_level, name").fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def load_last_run():
    with dbmod.connection() as conn:
        row = conn.execute("SELECT * FROM run_log ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def render():
    st.title("🇯🇵 日本向けサイバー脅威監視ダッシュボード")
    st.caption(
        "Blue Team / Threat Intelligence用途。公開情報の収集・整理・分析のみを行い、"
        "能動的な攻撃・スキャン・侵入は一切行いません。"
    )

    df = load_incidents_df()
    last_run = load_last_run()

    if last_run:
        st.info(
            f"最終収集実行: {last_run['started_at']} 〜 {last_run['finished_at']} / "
            f"成功ソース {last_run['sources_ok']} / 失敗ソース {last_run['sources_failed']} / "
            f"新規 {last_run['items_new']}件・更新 {last_run['items_updated']}件"
        )

    if df.empty:
        st.warning("データがまだありません。`python update.py` を実行してデータを収集してください。")
        return

    now = pd.Timestamp.now(tz="UTC")
    today = now.normalize()

    new_today = int((df["status"] == "NEW").sum())
    critical_high = int(df["severity"].isin(["Critical", "High"]).sum())
    japan_related = int((df["japan_relevance_score"] >= 40).sum())
    kev_cves = int((df["in_kev"] == 1).sum())
    ransomware_related = int(df["malware"].fillna("").str.contains("ransom", case=False).sum() +
                              df["attack_vector"].fillna("").str.contains("ransom|ランサム", case=False, regex=True).sum())
    apt_related = int(df["threat_actor"].fillna("").str.contains("apt", case=False).sum())

    st.subheader("サマリー")
    cols = st.columns(6)
    cols[0].metric("本日の新規脅威(NEW件数)", new_today)
    cols[1].metric("Critical / High", critical_high)
    cols[2].metric("日本関連 (Score≥40)", japan_related)
    cols[3].metric("悪用確認済みCVE(KEV)", kev_cves)
    cols[4].metric("ランサムウェア関連", ransomware_related)
    cols[5].metric("APT関連", apt_related)

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("業種別件数")
        sector_counts = df["sector"].fillna("不明").value_counts()
        st.bar_chart(sector_counts)
    with col_b:
        st.subheader("攻撃手法別件数")
        vector_counts = df["attack_vector"].fillna("不明").value_counts()
        st.bar_chart(vector_counts)

    st.subheader("直近7日間の推移(新規検出件数)")
    since = today - pd.Timedelta(days=6)
    recent = df[df["first_seen_at"] >= since]
    if not recent.empty:
        trend = recent.groupby(recent["first_seen_at"].dt.date).size()
        st.line_chart(trend)
    else:
        st.caption("直近7日間のデータがありません。")

    st.subheader("最新の重要事案一覧")
    display_cols = [
        "published_at", "status", "severity", "japan_relevance_score", "title",
        "target_org", "sector", "country", "cve_ids", "threat_actor", "source_name", "source_url",
    ]
    display_cols = [c for c in display_cols if c in df.columns]
    top = df.sort_values(
        ["severity", "japan_relevance_score", "published_at"],
        ascending=[True, False, False],
        key=lambda s: s.map({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}) if s.name == "severity" else s,
    ).head(50)
    st.dataframe(top[display_cols], use_container_width=True, hide_index=True)

    with st.expander("事実 / 未確認情報 / 分析・推測を確認する事案を選択"):
        options = top["title"].tolist()
        if options:
            chosen = st.selectbox("事案を選択", options)
            row = df[df["title"] == chosen].iloc[0]
            st.markdown(f"**確認済み事実**: {row.get('confirmed_facts') or '(一次情報での確認待ち)'}")
            st.markdown(f"**未確認情報**: {row.get('unconfirmed_info') or 'なし'}")
            st.markdown(f"**分析・推測**: {row.get('analysis_notes') or 'なし'}")
            st.markdown(f"**Japan Risk Score根拠**: {row.get('japan_relevance_reasons') or 'なし'}")
            st.markdown(f"**推奨対策**: {row.get('recommended_actions') or '(情報源を参照)'}")

    st.subheader("CVE一覧")
    cve_df = load_cves_df()
    st.dataframe(cve_df, use_container_width=True, hide_index=True)

    st.subheader("IOC一覧")
    ioc_df = load_iocs_df()
    if ioc_df.empty:
        st.caption("IOCはまだ抽出されていません。")
    else:
        st.dataframe(ioc_df, use_container_width=True, hide_index=True)

    st.subheader("情報源一覧")
    st.dataframe(load_sources_df(), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    render()