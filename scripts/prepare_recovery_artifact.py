#!/usr/bin/env python3
"""Export only recoverable SQLite observations and a checksum manifest.

Never export Git bundles/history, logs, arbitrary data files, report text, or
process/Git configuration. The original local recovery files are untouched.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile

DB_MEMBER = 'data/threat_intel.db'


def prepare(recovery_dir, output_dir, root=None):
    root = Path(root or Path.cwd()).resolve()
    output_dir = Path(output_dir).resolve()
    recovery_dir = Path(recovery_dir).resolve()
    if output_dir == root or root in output_dir.parents:
        raise ValueError('Artifact output must be outside checkout')
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix='snapshot-', dir=output_dir))
    snapshots = []
    # Recover the pre-rebase generation rather than a possibly conflicted worktree.
    for path in sorted(recovery_dir.glob('generation-*/generated.tar.gz')):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('Recovery archive symlinks are not allowed')
        with tarfile.open(path, 'r:gz') as source:
            members = [m for m in source.getmembers() if m.name == DB_MEMBER]
            if not members:
                continue
            if len(members) != 1 or not members[0].isfile():
                raise ValueError('Invalid SQLite recovery member')
            snapshots.append(source.extractfile(members[0]).read())
    if not snapshots:
        db = root / DB_MEMBER
        if db.exists():
            if db.is_symlink() or root not in db.resolve().parents:
                raise ValueError('SQLite must stay inside checkout')
            # A read-only backup also works when publication never started.
            with tempfile.TemporaryDirectory() as scratch:
                copy = Path(scratch) / 'copy.db'
                with sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True) as source:
                    with sqlite3.connect(copy) as target:
                        source.backup(target)
                snapshots.append(copy.read_bytes())
    records = []
    for number, content in enumerate(snapshots, 1):
        with tempfile.TemporaryDirectory() as scratch:
            check = Path(scratch) / 'check.db'
            check.write_bytes(content)
            with sqlite3.connect(check.as_uri() + '?mode=ro', uri=True) as connection:
                if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('SQLite recovery integrity check failed')
        name = f'database-{number}.tar.gz'
        pending = destination / f'.{name}.partial'
        with tarfile.open(pending, 'x:gz') as archive:
            member = tarfile.TarInfo(DB_MEMBER)
            member.size = len(content)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(content))
        pending.rename(destination / name)
        records.append(dict(file=name, member=DB_MEMBER, bytes=len(content),
                            sha256=hashlib.sha256(content).hexdigest()))
    manifest = dict(format_version=1, snapshots=records,
                    excluded=['git-history', 'git-config', 'environment', 'logs', 'reports', 'other-data-files'])
    pending_manifest = destination / '.manifest.partial'
    pending_manifest.write_text(json.dumps(manifest, indent=2))
    pending_manifest.rename(destination / 'manifest.json')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recovery-dir', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    prepare(args.recovery_dir, args.output_dir)
