#!/usr/bin/env python3
"""Publish generated files with normal fast-forward pushes and durable recovery files.

Never resolve generated-data conflicts by choosing a side. A new data generation
on main requires a fresh collection from main, not replaying an old SQLite file.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

GENERATED = ('data', 'daily_report.md', 'reports', 'docs/data')


def git(*args, check=True):
    return subprocess.run(['git', *args], check=check, text=True, capture_output=True)


def generated(path):
    return any(path == p or path.startswith(p + '/') for p in GENERATED)


def publish(backup_root, attempts=3):
    root = Path(git('rev-parse', '--show-toplevel').stdout.strip()).resolve()
    if Path.cwd().resolve() != root:
        raise RuntimeError('Run from the repository root')
    backup_root = Path(backup_root).resolve()
    if backup_root == root or root in backup_root.parents:
        raise RuntimeError('Recovery files must be outside the checkout')
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='generation-', dir=backup_root))
    print(f'Recovery files: {backup}', flush=True)
    base = git('rev-parse', 'HEAD').stdout.strip()
    # Back up before staging, rebasing or pushing; never overwrite earlier backups.
    with tarfile.open(backup / 'generated.tar.gz', 'x:gz') as archive:
        for name in (*GENERATED, 'logs'):
            if (root / name).exists():
                archive.add(root / name, arcname=name)
    (backup / 'manifest.json').write_text(json.dumps({'base': base,
        'created_at': datetime.now(timezone.utc).isoformat()}, indent=2))
    changed = git('diff', '--name-only', '-z', 'HEAD').stdout.split('\0')
    changed += git('ls-files', '--others', '--exclude-standard', '-z').stdout.split('\0')
    if any(p and not generated(p) for p in changed):
        raise RuntimeError('Refusing to publish with unrelated working-tree/index changes')
    paths = [p for p in GENERATED if (root / p).exists() or git('ls-files', '--', p).stdout]
    if paths:
        git('add', '--', *paths)
    if git('diff', '--cached', '--quiet', check=False).returncode == 0:
        print('No generated changes to publish')
        return
    if git('diff', '--cached', '--name-only', '--diff-filter=D').stdout:
        raise RuntimeError('Refusing to delete existing generated files')
    git('commit', '-m', f'chore: daily update {datetime.now(timezone.utc):%Y-%m-%d}')
    previous_rejected_tip = None
    for attempt in range(1, attempts + 1):
        git('bundle', 'create', str(backup / f'attempt-{attempt}.bundle'), 'HEAD')
        git('fetch', 'origin', 'refs/heads/main')
        remote = git('rev-parse', 'FETCH_HEAD').stdout.strip()
        head = git('rev-parse', 'HEAD').stdout.strip()
        if remote == head:
            print('Generation is already published')
            return
        if remote == previous_rejected_tip:
            raise RuntimeError('Push rejected without a main advance; check permissions/protection/network')
        if git('merge-base', '--is-ancestor', base, remote, check=False).returncode:
            raise RuntimeError('main no longer descends from the collection base; recovery retained')
        if git('diff', '--name-only', base, remote, '--', *GENERATED).stdout:
            raise RuntimeError('main contains newer generated data; recovery retained. Re-run collection from latest main')
        if git('merge-base', '--is-ancestor', remote, head, check=False).returncode:
            result = git('rebase', remote, check=False)
            if result.returncode:
                # Leave the failed state intact for inspection; no reset/clean/side selection.
                raise RuntimeError(f'Rebase failed; recovery retained: {result.stderr}')
        result = git('push', 'origin', 'HEAD:refs/heads/main', check=False)
        if result.returncode == 0:
            print(f'Published using a normal push (attempt {attempt})')
            return
        print(result.stderr, flush=True)
        previous_rejected_tip = remote
    raise RuntimeError('Concurrent main changes exhausted push attempts; recovery retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup-dir', required=True)
    args = parser.parse_args()
    try:
        publish(args.backup_dir)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'{exc}\n')
