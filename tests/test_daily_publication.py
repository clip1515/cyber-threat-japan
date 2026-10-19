"""Publication races use local repositories only; no GitHub access or production data."""
import importlib.util
from pathlib import Path
import shlex
import sqlite3
import subprocess

import pytest
import yaml

SPEC = importlib.util.spec_from_file_location('daily_publisher', Path(__file__).parents[1] / 'scripts/publish_daily_update.py')
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


def git(repo, *args, check=True):
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=check)


def commit(repo, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    git(repo, 'add', path)
    git(repo, 'commit', '-m', 'fixture update')


@pytest.fixture
def repositories(tmp_path, monkeypatch):
    remote, seed, runner, writer = [tmp_path / name for name in ('remote.git','seed','runner','writer')]
    subprocess.run(['git', 'init', '--bare', '--initial-branch=main', str(remote)], check=True, capture_output=True)
    git(tmp_path, 'clone', str(remote), str(seed))
    for repo in [seed]:
        git(repo, 'config', 'user.name', 'Fixture')
        git(repo, 'config', 'user.email', 'fixture@example.test')
    commit(seed, 'README.md', 'base\n')
    commit(seed, 'data/state.txt', 'base generation\n')
    git(seed, 'push', 'origin', 'HEAD:main')
    for repo in [runner, writer]:
        git(tmp_path, 'clone', str(remote), str(repo))
        git(repo, 'config', 'user.name', 'Fixture')
        git(repo, 'config', 'user.email', 'fixture@example.test')
    (runner/'data/state.txt').write_text('local generation\n')
    backup=tmp_path/'recovery'
    monkeypatch.chdir(runner)
    return remote, runner, writer, backup


def race_hook(runner, writer, path):
    # Git advertises the remote tip before invoking this hook. Advance it now.
    hook=runner/'.git/hooks/pre-push'
    marker=runner/'.git/race-fired'
    hook.write_text('#!/bin/sh\nset -eu\nif [ ! -f '+shlex.quote(str(marker))+' ]; then\n'
                    'touch '+shlex.quote(str(marker))+'\n'
                    'unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE\n'
                    'git -C '+shlex.quote(str(writer))+' add '+shlex.quote(path)+'\n'
                    'git -C '+shlex.quote(str(writer))+' commit -m race\n'
                    'git -C '+shlex.quote(str(writer))+' push origin HEAD:main\nfi\n')
    hook.chmod(0o755)


def test_normal_push_and_noop_do_not_create_extra_commits(repositories):
    remote,runner,writer,backup=repositories
    PUBLISHER.publish(backup)
    head=git(runner,'rev-parse','HEAD').stdout
    assert git(remote,'rev-parse','refs/heads/main').stdout==head
    PUBLISHER.publish(backup)
    assert git(runner,'rev-parse','HEAD').stdout==head
    assert len(list(backup.glob('generation-*/generated.tar.gz')))==2
    assert list(backup.glob('generation-*/attempt-1.bundle'))


def test_code_advance_is_rebased_without_losing_generation(repositories):
    remote,runner,writer,backup=repositories
    commit(writer,'README.md','remote code\n')
    git(writer,'push','origin','HEAD:main')
    PUBLISHER.publish(backup)
    assert git(remote,'show','main:README.md').stdout=='remote code\n'
    assert git(remote,'show','main:data/state.txt').stdout=='local generation\n'


def test_new_remote_data_is_never_overwritten(repositories):
    remote,runner,writer,backup=repositories
    commit(writer,'data/state.txt','remote generation\n')
    git(writer,'push','origin','HEAD:main')
    with pytest.raises(RuntimeError,match='newer generated data'):
        PUBLISHER.publish(backup)
    assert git(remote,'show','main:data/state.txt').stdout=='remote generation\n'
    assert (runner/'data/state.txt').read_text()=='local generation\n'
    assert list(backup.glob('generation-*/attempt-1.bundle'))


def test_push_race_after_rebase_is_retried_safely(repositories):
    remote,runner,writer,backup=repositories
    (writer/'README.md').write_text('raced code\n')
    race_hook(runner,writer,'README.md')
    PUBLISHER.publish(backup)
    assert git(remote,'show','main:README.md').stdout=='raced code\n'
    assert git(remote,'show','main:data/state.txt').stdout=='local generation\n'
    assert list(backup.glob('generation-*/attempt-2.bundle'))


def test_data_race_retains_both_generations(repositories):
    remote,runner,writer,backup=repositories
    (writer/'data/state.txt').write_text('raced generation\n')
    race_hook(runner,writer,'data/state.txt')
    with pytest.raises(RuntimeError,match='newer generated data'):
        PUBLISHER.publish(backup)
    assert git(remote,'show','main:data/state.txt').stdout=='raced generation\n'
    assert (runner/'data/state.txt').read_text()=='local generation\n'


def test_permission_rejection_is_not_retried_as_a_race(repositories):
    remote,runner,writer,backup=repositories
    hook=remote/'hooks/pre-receive'
    hook.write_text('#!/bin/sh\nexit 1\n');hook.chmod(0o755)
    with pytest.raises(RuntimeError,match='without a main advance'):
        PUBLISHER.publish(backup)
    assert git(remote,'show','main:data/state.txt').stdout=='base generation\n'
    assert list(backup.glob('generation-*/generated.tar.gz'))


def test_existing_data_deletion_is_rejected(repositories):
    remote,runner,writer,backup=repositories
    # Simulate a collector deleting a tracked file, solely inside this fixture.
    (runner/'data/state.txt').unlink()
    with pytest.raises(RuntimeError,match='delete existing generated files'):
        PUBLISHER.publish(backup)
    assert git(remote,'show','main:data/state.txt').stdout=='base generation\n'


def test_workflow_serializes_events_and_preserves_recovery():
    text=(Path(__file__).parents[1]/'.github/workflows/daily.yml').read_text()
    workflow=yaml.safe_load(text)
    assert workflow['jobs']['update']['if']=="github.ref == 'refs/heads/main'"
    assert workflow['concurrency']==dict(group='daily-update',**{'cancel-in-progress':False})
    steps=workflow['jobs']['update']['steps']
    checkout=next(s for s in steps if s.get('uses')=='actions/checkout@v4')
    assert checkout['with']=={'ref':'main','fetch-depth':0}
    upload=next(s for s in steps if s.get('uses')=='actions/upload-artifact@v4')
    assert upload['if']=='always()'
    assert 'daily-update-recovery' in upload['with']['path']
    assert 'force' not in text.lower()


def test_old_push_after_successful_rebase_reproduces_fetch_first(repositories):
    remote,runner,writer,backup=repositories
    git(runner,'add','data')
    git(runner,'commit','-m','old daily generation')
    git(runner,'pull','--rebase','origin','main')
    commit(writer,'README.md','concurrent update\n')
    git(writer,'push','origin','HEAD:main')
    rejected=git(runner,'push','origin','HEAD:main',check=False)
    assert rejected.returncode != 0
    assert 'fetch first' in rejected.stderr or 'non-fast-forward' in rejected.stderr


def sqlite_generations(runner, writer):
    path=runner/'data/threat_intel.db'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE observations(value TEXT)')
        c.execute("INSERT INTO observations VALUES ('base')")
    git(runner,'add','data')
    git(runner,'commit','-m','database baseline')
    git(runner,'push','origin','HEAD:main')
    git(writer,'fetch','origin','main')
    git(writer,'merge','--ff-only','origin/main')
    for repo,value in [(runner,'local'),(writer,'remote')]:
        with sqlite3.connect(repo/'data/threat_intel.db') as c:
            c.execute('INSERT INTO observations VALUES (?)',(value,))
    git(writer,'add','data')
    git(writer,'commit','-m','remote observations')
    git(writer,'push','origin','HEAD:main')


def test_old_rebase_cannot_merge_sqlite_generations(repositories):
    remote,runner,writer,backup=repositories
    sqlite_generations(runner,writer)
    git(runner,'add','data')
    git(runner,'commit','-m','local observations')
    result=git(runner,'pull','--rebase','origin','main',check=False)
    assert result.returncode != 0
    assert 'CONFLICT' in result.stdout or 'CONFLICT' in result.stderr


def test_safe_publish_keeps_sqlite_generations_and_recoverable_bundle(repositories,tmp_path):
    import tarfile
    remote,runner,writer,backup=repositories
    sqlite_generations(runner,writer)
    with pytest.raises(RuntimeError,match='newer generated data'):
        PUBLISHER.publish(backup)
    with sqlite3.connect(writer/'data/threat_intel.db') as c:
        assert c.execute('SELECT value FROM observations').fetchall()==[('base',),('remote',)]
    with sqlite3.connect(runner/'data/threat_intel.db') as c:
        assert c.execute('SELECT value FROM observations').fetchall()==[('base',),('local',)]
    generation=next(backup.glob('generation-*'))
    with tarfile.open(generation/'generated.tar.gz') as archive:
        recovered=tmp_path/'archived.db'
        recovered.write_bytes(archive.extractfile('data/threat_intel.db').read())
    with sqlite3.connect(recovered) as c:
        assert c.execute('SELECT value FROM observations').fetchall()==[('base',),('local',)]
    git(runner,'bundle','verify',str(generation/'attempt-1.bundle'))


def test_rebase_failure_preserves_backup_and_never_pushes(repositories,monkeypatch):
    remote,runner,writer,backup=repositories
    commit(writer,'README.md','new code\n')
    git(writer,'push','origin','HEAD:main')
    actual=PUBLISHER.git
    def failed(*args,**kwargs):
        if args[0]=='rebase':
            return subprocess.CompletedProcess(args,1,'','simulated rebase failure')
        return actual(*args,**kwargs)
    monkeypatch.setattr(PUBLISHER,'git',failed)
    with pytest.raises(RuntimeError,match='Rebase failed'):
        PUBLISHER.publish(backup)
    assert git(remote,'show','main:data/state.txt').stdout=='base generation\n'
    assert list(backup.glob('generation-*/generated.tar.gz'))


def test_repeated_races_stop_at_limit_without_force(repositories,monkeypatch):
    remote,runner,writer,backup=repositories
    actual=PUBLISHER.git
    pushes=[]
    def raced(*args,**kwargs):
        if args[0]=='push':
            git(writer,'fetch','origin','main')
            git(writer,'merge','--ff-only','origin/main')
            commit(writer,'README.md',f'race {len(pushes)}\n')
            git(writer,'push','origin','HEAD:main')
            pushes.append(args)
        return actual(*args,**kwargs)
    monkeypatch.setattr(PUBLISHER,'git',raced)
    with pytest.raises(RuntimeError,match='exhausted'):
        PUBLISHER.publish(backup,attempts=3)
    assert len(pushes)==3
    assert all(args==('push','origin','HEAD:refs/heads/main') for args in pushes)
    assert len(list(backup.glob('generation-*/attempt-*.bundle')))==3
    assert git(remote,'show','main:data/state.txt').stdout=='base generation\n'
