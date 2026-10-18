"""Audit regressions: all writes are confined to temporary SQLite databases."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from collectors.base import RawItem
from collectors.rss_collector import RssCollector
from database import db
import update


@pytest.fixture
def conn(tmp_path):
    with patch.object(db, 'DB_PATH', tmp_path / 'test.db'):
        db.init_db()
        with db.connection() as connection:
            yield connection


def item(title='Advisory', url='https://www.jpcert.or.jp/at/2026/at260029.html', text='', **extra):
    return RawItem('jpcert_alert', 'JPCERT/CC', 1, title, url,
                   published_at='2026-10-02T05:15:00+00:00', raw_text=text or title, extra=extra)


def test_distinct_products_are_not_fuzzy_merged(conn):
    for product in ['Splunk', 'Cisco', 'Elastic', 'Atlassian', 'Microsoft']:
        update.process_item(conn, item(f'Weekly Report: 複数の{product}製品に脆弱性',
                                      f'https://www.jpcert.or.jp/wr/2026/report.html#{product}'))
    assert conn.execute('SELECT count(*) FROM incidents').fetchone()[0] == 5


def test_same_url_with_new_cves_keeps_identity_and_history(conn):
    original = item()
    update.process_item(conn, original)
    row = conn.execute('SELECT * FROM incidents').fetchone()
    update.process_item(conn, item(text='CVE-2026-88771 CVE-2026-88772'))
    rows = conn.execute('SELECT * FROM incidents').fetchall()
    assert len(rows) == 1
    assert rows[0]['id'] == row['id']
    assert rows[0]['cve_ids'] == 'CVE-2026-88771,CVE-2026-88772'
    assert conn.execute('SELECT count(*) FROM status_history').fetchone()[0] >= 1


def test_same_title_different_urls_is_not_one_article(conn):
    update.process_item(conn, item(url='https://example.test/1'))
    update.process_item(conn, item(url='https://example.test/2'))
    assert conn.execute('SELECT count(*) FROM incidents').fetchone()[0] == 2


def test_existing_kev_and_cvss_survive_rss_refresh(conn):
    update.process_item(conn, item(text='CVE-2026-88771', in_kev=True, cvss=9.8))
    update.process_item(conn, item(text='CVE-2026-88771'))
    row = conn.execute('SELECT * FROM incidents').fetchone()
    assert (row['severity'], row['in_kev'], row['cvss']) == ('Critical', 1, 9.8)


def test_refresh_repairs_existing_low_kev_without_deleting_history(conn):
    update.process_item(conn, item(text='CVE-2026-88771', in_kev=True))
    conn.execute("UPDATE incidents SET severity='Low'")
    update.process_item(conn, item(text='CVE-2026-88771'))
    assert conn.execute('SELECT severity FROM incidents').fetchone()[0] == 'High'
    assert conn.execute('SELECT count(*) FROM status_history').fetchone()[0] >= 1


def test_known_cve_cvss_is_used_without_kev(conn):
    db.upsert_cve(conn, 'CVE-2026-88771', cvss=9.8)
    update.process_item(conn, item(text='CVE-2026-88771'))
    assert conn.execute('SELECT severity FROM incidents').fetchone()[0] == 'Critical'


def test_same_article_preserves_first_seen_on_revision(conn):
    update.process_item(conn, item())
    first_seen = conn.execute('SELECT first_seen_at FROM incidents').fetchone()[0]
    revision = item(source_updated_at='2026-10-16')
    revision.published_at = '2026-09-28'
    update.process_item(conn, revision)
    row = conn.execute('SELECT * FROM incidents').fetchone()
    assert row['first_seen_at'] == first_seen
    assert row['published_at'] == '2026-09-28'
    assert row['source_updated_at'] == '2026-10-16'


def test_known_cve_kev_is_used_for_multi_cve_article_without_spreading_it(conn):
    db.upsert_cve(conn, 'CVE-2026-88771', in_kev=1)
    update.process_item(conn, item(text='CVE-2026-88771 CVE-2026-88772'))
    row = conn.execute('SELECT * FROM incidents').fetchone()
    assert (row['severity'], row['in_kev']) == ('High', 1)
    assert conn.execute("SELECT in_kev FROM cves WHERE cve_id='CVE-2026-88772'").fetchone()[0] == 0


def test_explicit_cves_do_not_hide_body_cves(conn):
    update.process_item(conn, item(text='CVE-2026-88772', cve_ids=['CVE-2026-88771']))
    assert conn.execute('SELECT cve_ids FROM incidents').fetchone()[0] == 'CVE-2026-88771,CVE-2026-88772'


def test_unknown_publication_is_not_collection_time(conn):
    incoming = item()
    incoming.published_at = None
    update.process_item(conn, incoming)
    assert conn.execute('SELECT published_at FROM incidents').fetchone()[0] is None


FEED = b'''<feed xmlns="http://www.w3.org/2005/Atom"><title>JPCERT</title>
<entry><title>NetScaler (\xe6\x9b\xb4\xe6\x96\xb0)</title><id>one</id>
<link href="https://www.jpcert.or.jp/at/2026/at260029.html"/>
<updated>2026-10-02T14:15:00+09:00</updated></entry></feed>'''
BODY = '''<html><nav>CVE-2026-99999</nav><article><div class="at">
JPCERT/CC<br>2026-09-28（公開）<br>2026-10-02（更新）<br>
<h4>I. 概要</h4>CVE-2026-88771 CVE-2026-88772 CVE-2026-88773 CVE-2026-88774
CVE-2026-88775 CVE-2026-88776 CVE-2026-88777 CVE-2026-88778
</div></article><footer>CVE-2026-99998</footer></html>'''.encode()


def collect(body=BODY):
    collector = RssCollector(dict(id='jpcert_alert', name='JPCERT/CC', trust_level=1,
                                 url='https://www.jpcert.or.jp/rss/jpcert.rdf'))
    def get(url):
        if url.endswith('.rdf'):
            return SimpleNamespace(content=FEED)
        if isinstance(body, Exception):
            raise body
        return SimpleNamespace(content=body)
    with patch('collectors.rss_collector.http_get', side_effect=get):
        return collector.collect()


def test_article_publication_and_update_are_separate(conn):
    incoming = collect()[0]
    assert incoming.published_at == '2026-09-28'
    assert incoming.extra['source_updated_at'].startswith('2026-10-02')
    update.process_item(conn, incoming)
    row = conn.execute('SELECT * FROM incidents').fetchone()
    assert row['published_at'] == '2026-09-28'
    assert row['source_updated_at'].startswith('2026-10-02')


def test_article_body_cves_exclude_navigation(conn):
    update.process_item(conn, collect()[0])
    row = conn.execute('SELECT * FROM incidents').fetchone()
    assert row['cve_ids'].split(',') == [f'CVE-2026-{n}' for n in range(88771, 88779)]


def test_article_fetch_failure_preserves_feed_and_unknown_publication(caplog):
    incoming = collect(RuntimeError('timeout'))[0]
    assert incoming.published_at is None
    assert incoming.extra['source_updated_at'] == '2026-10-02T05:15:00+00:00'
    assert 'timeout' in caplog.text


def test_explicit_feed_publication_and_update_remain_distinct():
    feed = FEED.replace(b'<updated>', b'<published>2026-09-28T09:00:00+09:00</published><updated>')
    collector = RssCollector(dict(id='jpcert_alert', name='JPCERT/CC', trust_level=1,
                                 url='https://www.jpcert.or.jp/rss/jpcert.rdf'))
    with patch('collectors.rss_collector.http_get', side_effect=[SimpleNamespace(content=feed), RuntimeError('timeout')]):
        incoming = collector.collect()[0]
    assert incoming.published_at == '2026-09-28T00:00:00+00:00'
    assert incoming.extra['source_updated_at'] == '2026-10-02T05:15:00+00:00'


def test_migration_preserves_existing_rows_and_is_repeatable(conn):
    conn.execute("INSERT INTO incidents (dedup_key,title) VALUES ('old','preserve me')")
    conn.commit()
    db.init_db()
    db.init_db()
    assert conn.execute("SELECT title FROM incidents WHERE dedup_key='old'").fetchone()[0] == 'preserve me'
    assert 'source_updated_at' in {r['name'] for r in conn.execute('PRAGMA table_info(incidents)')}


def test_cross_source_merge_keeps_all_url_identities(conn):
    update.process_item(conn, item(url='https://example.test/a', text='CVE-2026-88771'))
    update.process_item(conn, item(url='https://example.test/b', text='CVE-2026-88771'))
    for _ in range(2):
        update.process_item(conn, item(url='https://example.test/a'))
        update.process_item(conn, item(url='https://example.test/b', text='CVE-2026-88771'))
    assert conn.execute('SELECT count(*) FROM incidents').fetchone()[0] == 1


def test_partial_summary_does_not_lower_ransomware_severity(conn):
    update.process_item(conn, item(text='ransomware campaign'))
    update.process_item(conn, item(text='brief follow-up'))
    assert conn.execute('SELECT severity FROM incidents').fetchone()[0] == 'High'


def test_single_cve_metadata_is_not_assigned_to_other_article_cves(conn):
    update.process_item(conn, item(text='CVE-2026-88771 CVE-2026-88772'))
    update.process_item(conn, item(text='CVE-2026-88771', cve_ids=['CVE-2026-88771'],
                                  in_kev=True, cvss=9.8))
    unrelated = conn.execute("SELECT cvss,in_kev FROM cves WHERE cve_id='CVE-2026-88772'").fetchone()
    assert tuple(unrelated) == (None, 0)


def test_cve_table_cvss_does_not_regress_on_lower_score(conn):
    db.upsert_cve(conn, 'CVE-2026-88771', cvss=9.8)
    db.upsert_cve(conn, 'CVE-2026-88771', cvss=4.0)
    assert conn.execute("SELECT cvss FROM cves WHERE cve_id='CVE-2026-88771'").fetchone()[0] == 9.8


def test_url_keyed_article_with_later_cves_matches_other_source(conn):
    update.process_item(conn, item(url='https://example.test/a'))
    update.process_item(conn, item(url='https://example.test/a', text='CVE-2026-88771'))
    update.process_item(conn, item(url='https://example.test/b', text='CVE-2026-88771'))
    assert conn.execute('SELECT count(*) FROM incidents').fetchone()[0] == 1
    assert db.find_incident_by_url(conn, 'https://example.test/a')['id'] == db.find_incident_by_url(conn, 'https://example.test/b')['id']


def test_db_write_cannot_downgrade_risk(conn):
    update.process_item(conn, item(text='CVE-2026-88771', in_kev=True, cvss=9.8))
    row = conn.execute('SELECT * FROM incidents').fetchone()
    db.upsert_incident(conn, dict(dedup_key=row['dedup_key'], severity='Low', cvss=1.0, in_kev=0))
    result = conn.execute('SELECT severity,cvss,in_kev FROM incidents').fetchone()
    assert tuple(result) == ('Critical', 9.8, 1)


def test_new_source_does_not_inherit_another_sources_update_date(conn):
    update.process_item(conn, item(url='https://example.test/a', text='CVE-2026-88771',
                                  source_updated_at='2026-10-02'))
    other = item(url='https://example.test/b', text='CVE-2026-88771')
    other.published_at = None
    update.process_item(conn, other)
    row = conn.execute('SELECT source_url,published_at,source_updated_at FROM incidents').fetchone()
    assert tuple(row) == ('https://example.test/b', None, None)


def test_alias_migration_does_not_delete_historical_duplicates(conn):
    conn.execute("INSERT INTO incidents (dedup_key,title,source_url) VALUES ('old-a','A','https://old.test/a')")
    conn.execute("INSERT INTO incidents (dedup_key,title,source_url) VALUES ('old-b','B','https://old.test/a')")
    conn.commit()
    ids = [r['id'] for r in conn.execute('SELECT id FROM incidents ORDER BY id')]
    db.init_db()
    db.init_db()
    assert [r['id'] for r in conn.execute('SELECT id FROM incidents ORDER BY id')] == ids
    assert db.find_incident_by_url(conn, 'https://old.test/a')['id'] == min(ids)
    assert not conn.execute('PRAGMA foreign_key_check').fetchall()


def test_failed_column_migration_rolls_back_all_column_additions(tmp_path):
    import sqlite3
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as c:
        c.executescript('CREATE TABLE incidents(id INTEGER PRIMARY KEY, source_url TEXT); '
                        'CREATE TABLE status_history(id INTEGER PRIMARY KEY);')
    def connection():
        c = sqlite3.connect(path)
        calls = []
        def authorize(action, *args):
            if action == sqlite3.SQLITE_ALTER_TABLE:
                calls.append(action)
                if len(calls) == 2:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        c.set_authorizer(authorize)
        return c
    with patch.object(db, 'get_connection', side_effect=connection):
        with pytest.raises(sqlite3.DatabaseError):
            db._migrate_legacy_schema()
    with sqlite3.connect(path) as c:
        assert [r[1] for r in c.execute('PRAGMA table_info(incidents)')] == ['id', 'source_url']
