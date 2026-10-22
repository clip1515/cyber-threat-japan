"""Phase 2-D: collection vs. migration races, on synthetic data only.

Git races use a local bare repository and local clones; SQLite races use
temporary files. No GitHub access, no production database, no notifications.
"""
import contextlib
import importlib.util
import shlex
import sqlite3
import subprocess
import tarfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from collectors.base import RawItem
from database import db
from database import migrate_phase2 as mig
import update

SPEC = importlib.util.spec_from_file_location(
    "phase2_publisher", Path(__file__).parents[1] / "scripts/publish_daily_update.py")
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)

SOURCES = [("jpcert_alert", "JPCERT/CC 注意喚起", 1), ("cisa_kev", "CISA Known Exploited Vulnerabilities Catalog", 1)]
DB = "data/threat_intel.db"


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check)


def item(url, title, text="", source="jpcert_alert", **extra):
    name = dict((s, n) for s, n, _ in SOURCES)[source]
    return RawItem(source, name, 1, title, url, published_at="2026-10-01T00:00:00+00:00",
                   raw_text=text or title, extra=extra)


def connect(repo):
    conn = sqlite3.connect(repo / DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def daily_run(repo, items):
    """What update.main() does to the database, minus collection and output files."""
    with contextlib.closing(connect(repo)) as conn:
        run_id = db.start_run(conn)
        conn.commit()
        for i in items:
            update.process_item(conn, i, run_id=run_id)
            conn.commit()
        db.finish_run(conn, run_id, 1, 0, len(items), len(items), 0, notes="synthetic")
        conn.commit()
        return run_id


def migration_run(repo):
    with contextlib.closing(connect(repo)) as conn:
        return mig.migrate(conn)


def incidents(conn):
    return {r["dedup_key"]: r["id"] for r in conn.execute("SELECT id, dedup_key FROM incidents")}


def remote_state(tmp_path, remote, name="inspect"):
    checkout = tmp_path / name
    git(tmp_path, "clone", "-q", str(remote), str(checkout))
    return checkout


def assert_publication_invariants(tmp_path, remote, required_commits, required_dedup_keys, name="inspect"):
    """Shared detector: no lost history, no lost legacy rows, no duplicates, valid DB."""
    checkout = remote_state(tmp_path, remote, name)
    for sha in required_commits:
        assert git(checkout, "merge-base", "--is-ancestor", sha, "HEAD", check=False).returncode == 0, \
            f"published history lost commit {sha}"
    with contextlib.closing(connect(checkout)) as conn:
        keys = [r[0] for r in conn.execute("SELECT dedup_key FROM incidents")]
        assert len(keys) == len(set(keys)), "duplicate incidents"
        missing = set(required_dedup_keys) - set(keys)
        assert not missing, f"published DB lost incidents {missing}"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    return checkout


@pytest.fixture
def repos(tmp_path, monkeypatch):
    remote, seed = tmp_path / "remote.git", tmp_path / "seed"
    subprocess.run(["git", "init", "-q", "--bare", "--initial-branch=main", str(remote)], check=True)
    git(tmp_path, "clone", "-q", str(remote), str(seed))
    (seed / "data").mkdir()
    with contextlib.closing(sqlite3.connect(seed / DB)) as conn:
        conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.executemany("INSERT INTO sources (id, name, type, url, trust_level) VALUES (?, ?, 'rss', 'https://s.test', ?)",
                         SOURCES)
        conn.commit()
    daily_run(seed, [item("https://old.test/1", "Existing advisory")])
    (seed / "README.md").write_text("synthetic\n")
    for repo in (seed,):
        git(repo, "config", "user.name", "Fixture")
        git(repo, "config", "user.email", "fixture@example.test")
    git(seed, "add", ".")
    git(seed, "commit", "-q", "-m", "seed")
    git(seed, "push", "-q", "origin", "HEAD:main")
    clones = {}
    for name in ("daily", "migrator", "migrator2", "rerun"):
        clones[name] = tmp_path / name
    for name in ("daily", "migrator", "migrator2"):
        clone(tmp_path, remote, clones[name])
    return tmp_path, remote, clones


def clone(tmp_path, remote, path):
    git(tmp_path, "clone", "-q", str(remote), str(path))
    git(path, "config", "user.name", "Fixture")
    git(path, "config", "user.email", "fixture@example.test")


def publish(repo, backup, monkeypatch):
    monkeypatch.chdir(repo)
    PUBLISHER.publish(backup)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def backup_db(backup_root, workdir):
    """Extract the database kept in the newest recovery archive."""
    archive = sorted(Path(backup_root).glob("generation-*/generated.tar.gz"), key=lambda p: p.stat().st_mtime)[-1]
    with tarfile.open(archive) as tar:
        tar.extract(DB, workdir, filter="data")
    return Path(workdir) / DB


NEW_ITEMS = [item("https://new.test/kev", "New KEV advisory", "CVE-2026-93001",
                  source="cisa_kev", cve_ids=["CVE-2026-93001"], in_kev=True),
             item("https://new.test/2", "New advisory")]


class TestGitRaces:
    def test_c_d_same_old_base_daily_first_migration_refused(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        daily_run(c["daily"], NEW_ITEMS)
        migration_run(c["migrator"])
        with contextlib.closing(connect(c["daily"])) as conn:
            daily_keys = set(incidents(conn))
        daily_head = publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        with pytest.raises(RuntimeError, match="newer generated data"):
            publish(c["migrator"], tmp_path / "rec-mig", monkeypatch)
        checkout = assert_publication_invariants(tmp_path, remote, [daily_head], daily_keys)
        with contextlib.closing(connect(checkout)) as conn:
            assert "articles" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        # The refused migration is kept for inspection, not lost.
        kept = backup_db(tmp_path / "rec-mig", tmp_path / "kept")
        with contextlib.closing(sqlite3.connect(kept)) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 2

    def test_d_migration_first_then_stale_daily_refused_e_rerun_from_latest(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        migration_run(c["migrator"])
        daily_run(c["daily"], NEW_ITEMS)
        mig_head = publish(c["migrator"], tmp_path / "rec-mig", monkeypatch)
        with pytest.raises(RuntimeError, match="newer generated data"):
            publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        # E: the daily workflow checks out ref: main again, so a re-run starts from the migrated DB.
        clone(tmp_path, remote, c["rerun"])
        rerun_id = daily_run(c["rerun"], NEW_ITEMS)
        with contextlib.closing(connect(c["rerun"])) as conn:
            keys = set(incidents(conn))
            stale = conn.execute("SELECT count(*) FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM "
                                 "incident_observations o WHERE o.incident_id = i.id)").fetchone()[0]
            kev_run = conn.execute("SELECT kev_first_seen_run_id FROM cves WHERE cve_id = 'CVE-2026-93001'"
                                   ).fetchone()[0]
        # Legacy collection does not write Phase 2 tables: they lag until the next migration run.
        assert stale == 2
        assert kev_run == rerun_id
        rerun_head = publish(c["rerun"], tmp_path / "rec-rerun", monkeypatch)
        assert_publication_invariants(tmp_path, remote, [mig_head, rerun_head], keys)

    def test_e_refused_migration_rerun_from_latest_main_catches_up_without_duplicates(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        daily_id = daily_run(c["daily"], NEW_ITEMS)
        migration_run(c["migrator"])
        daily_head = publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        with pytest.raises(RuntimeError):
            publish(c["migrator"], tmp_path / "rec-mig", monkeypatch)
        clone(tmp_path, remote, c["rerun"])
        report = migration_run(c["rerun"])
        rerun_head = publish(c["rerun"], tmp_path / "rec-rerun", monkeypatch)
        with contextlib.closing(connect(c["daily"])) as conn:
            daily_keys = set(incidents(conn))
        checkout = assert_publication_invariants(tmp_path, remote, [daily_head, rerun_head], daily_keys, "final")
        with contextlib.closing(connect(checkout)) as conn:
            assert conn.execute("SELECT kev_first_seen_run_id FROM cves WHERE cve_id = 'CVE-2026-93001'"
                                ).fetchone()[0] == daily_id
            assert conn.execute("SELECT count(*) FROM incident_observations").fetchone()[0] == \
                conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
            assert conn.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
        assert report["inserted"]["incident_observations"] == 3

    def test_push_race_between_fetch_and_push_is_refused_not_overwritten(self, repos, monkeypatch):
        """The other runner pushes after our fetch/HEAD check but before our push lands."""
        tmp_path, remote, c = repos
        daily_run(c["daily"], NEW_ITEMS)
        migration_run(c["migrator"])
        git(c["daily"], "add", DB)
        git(c["daily"], "commit", "-q", "-m", "daily generation")
        hook = c["migrator"] / ".git/hooks/pre-push"
        marker = c["migrator"] / ".git/race-fired"
        hook.write_text("#!/bin/sh\nset -eu\nif [ ! -f " + shlex.quote(str(marker)) + " ]; then\n"
                        "touch " + shlex.quote(str(marker)) + "\nunset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE\n"
                        "git -C " + shlex.quote(str(c["daily"])) + " push -q origin HEAD:main\nfi\n")
        hook.chmod(0o755)
        with pytest.raises(RuntimeError, match="newer generated data"):
            publish(c["migrator"], tmp_path / "rec-mig", monkeypatch)
        daily_head = git(c["daily"], "rev-parse", "HEAD").stdout.strip()
        assert git(remote, "rev-parse", "refs/heads/main").stdout.strip() == daily_head
        with contextlib.closing(connect(c["daily"])) as conn:
            assert_publication_invariants(tmp_path, remote, [daily_head], set(incidents(conn)))

    def test_rerun_after_successful_publish_adds_nothing(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        daily_run(c["daily"], NEW_ITEMS)
        publish(c["daily"], tmp_path / "rec-1", monkeypatch)
        clone(tmp_path, remote, c["rerun"])
        with contextlib.closing(connect(c["rerun"])) as conn:
            before = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
        daily_run(c["rerun"], NEW_ITEMS)
        with contextlib.closing(connect(c["rerun"])) as conn:
            assert conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == before
            assert conn.execute("SELECT count(DISTINCT kev_first_seen_run_id) FROM cves "
                                "WHERE kev_first_seen_run_id IS NOT NULL").fetchone()[0] == 1


class TestNegativeControls:
    """Unsafe publishers must be caught by assert_publication_invariants."""

    def test_force_push_publisher_is_detected(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        daily_run(c["daily"], NEW_ITEMS)
        migration_run(c["migrator"])
        with contextlib.closing(connect(c["daily"])) as conn:
            daily_keys = set(incidents(conn))
        daily_head = publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        git(c["migrator"], "add", DB)
        git(c["migrator"], "commit", "-q", "-m", "unsafe")
        git(c["migrator"], "push", "-q", "--force", "origin", "HEAD:main")
        with pytest.raises(AssertionError, match="lost commit"):
            assert_publication_invariants(tmp_path, remote, [daily_head], daily_keys)

    def test_side_selecting_rebase_is_detected(self, repos, monkeypatch):
        tmp_path, remote, c = repos
        daily_run(c["daily"], NEW_ITEMS)
        migration_run(c["migrator"])
        with contextlib.closing(connect(c["daily"])) as conn:
            daily_keys = set(incidents(conn))
        daily_head = publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        git(c["migrator"], "add", DB)
        git(c["migrator"], "commit", "-q", "-m", "unsafe")
        git(c["migrator"], "fetch", "-q", "origin")
        # "Resolve" the binary conflict by keeping the migrator's stale database.
        git(c["migrator"], "rebase", "-X", "theirs", "origin/main")
        git(c["migrator"], "push", "-q", "origin", "HEAD:main")
        with pytest.raises(AssertionError, match="lost incidents"):
            assert_publication_invariants(tmp_path, remote, [daily_head], daily_keys)

    def test_publisher_without_generated_data_guard_publishes_inconsistent_outputs(self, repos, monkeypatch):
        """scripts/publish_daily_update.py:82 is what stops a rebase from mixing generations."""
        tmp_path, remote, c = repos
        # The other runner changed only the dashboard JSON; ours changed only the DB.
        (c["daily"] / "docs/data").mkdir(parents=True)
        (c["daily"] / "docs/data/dashboard_data.json").write_text('{"last_run": {"id": 99}}')
        daily_head = publish(c["daily"], tmp_path / "rec-daily", monkeypatch)
        migration_run(c["migrator"])
        migration_run(c["migrator2"])
        with pytest.raises(RuntimeError, match="newer generated data"):
            publish(c["migrator2"], tmp_path / "rec-real", monkeypatch)
        source = (Path(__file__).parents[1] / "scripts/publish_daily_update.py").read_text()
        guard = "        if git('diff', '--name-only', base, remote, '--', *GENERATED).stdout:\n"
        assert guard in source
        mutated = source.replace(guard, "        if False:\n")
        namespace = {"__name__": "mutated_publisher"}
        exec(compile(mutated, "mutated_publisher", "exec"), namespace)
        monkeypatch.chdir(c["migrator"])
        namespace["publish"](tmp_path / "rec-mutated")  # succeeds: JSON and DB now from different generations
        checkout = remote_state(tmp_path, remote, "mixed")
        assert (checkout / "docs/data/dashboard_data.json").exists()
        with contextlib.closing(connect(checkout)) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
        assert git(checkout, "merge-base", "--is-ancestor", daily_head, "HEAD", check=False).returncode == 0


class TestSameFileLocking:
    """A/B on one SQLite file (only possible when both run on the same machine)."""

    @pytest.fixture
    def path(self, tmp_path):
        p = tmp_path / "t.db"
        with contextlib.closing(sqlite3.connect(p)) as conn:
            conn.executescript(db.SCHEMA_PATH.read_text(encoding="utf-8"))
            conn.executemany("INSERT INTO sources (id, name, type, url, trust_level) VALUES (?, ?, 'rss', 'x', ?)",
                             SOURCES)
            conn.commit()
        return p

    def test_a_migration_started_during_daily_write_fails_cleanly(self, path):
        daily = sqlite3.connect(path)
        daily.row_factory = sqlite3.Row
        update.process_item(daily, item("https://a.test/1", "In-flight item"))
        assert daily.in_transaction  # the item's write transaction is still open
        with contextlib.closing(sqlite3.connect(path, timeout=0.1)) as other:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                mig.migrate(other)
            assert other.execute("PRAGMA user_version").fetchone()[0] == 0
        daily.commit()
        daily.close()
        with contextlib.closing(sqlite3.connect(path)) as conn:
            report = mig.migrate(conn)
        assert report["inserted"]["incident_observations"] == 1

    def test_b_daily_item_during_migration_fails_without_partial_writes(self, path):
        started, release = threading.Event(), threading.Event()
        errors = []

        def hold(conn, report, now):
            started.set()
            release.wait(5)

        def run_migration():
            try:
                with contextlib.closing(sqlite3.connect(path)) as conn:
                    mig.migrate(conn)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        with patch.object(mig, "STEPS", mig.STEPS + (hold,)):
            worker = threading.Thread(target=run_migration)
            worker.start()
            assert started.wait(5)
            with contextlib.closing(sqlite3.connect(path, timeout=0.1)) as daily:
                daily.row_factory = sqlite3.Row
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    update.process_item(daily, item("https://b.test/1", "Blocked item"))
            release.set()
            worker.join(5)
        assert not errors
        with contextlib.closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            assert conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
            update.process_item(conn, item("https://b.test/1", "Blocked item"))  # the retry succeeds
            conn.commit()
            assert conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
