import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile

import pytest
import yaml

SCRIPT=Path(__file__).parents[1]/'scripts/prepare_recovery_artifact.py'
spec=importlib.util.spec_from_file_location('minimal_artifact',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def database(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE observations(value TEXT)')
        c.execute('INSERT INTO observations VALUES (?)',(value,))


def restored(destination,tmp_path):
    manifest=json.loads((destination/'manifest.json').read_text())
    record=manifest['snapshots'][0]
    with tarfile.open(destination/record['file']) as tar:
        assert tar.getnames()==['data/threat_intel.db']
        content=tar.extractfile('data/threat_intel.db').read()
    assert hashlib.sha256(content).hexdigest()==record['sha256']
    copy=tmp_path/'restored.db';copy.write_bytes(content)
    with sqlite3.connect(copy) as c:return c.execute('SELECT value FROM observations').fetchall()


def test_fallback_exports_only_db_and_checksums(tmp_path):
    root=tmp_path/'repo';root.mkdir()
    database(root/'data/threat_intel.db','synthetic observation')
    for name in ['logs/update.log','data/credentials.txt','reports/report.md','.git/config','.env']:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('synthetic-secret-must-not-be-exported')
    recovery=tmp_path/'recovery';recovery.mkdir()
    (recovery/'history.bundle').write_text('synthetic-secret-in-old-history')
    output=module.prepare(recovery,tmp_path/'output',root)
    assert {p.name for p in output.iterdir()}=={'database-1.tar.gz','manifest.json'}
    assert restored(output,tmp_path)==[('synthetic observation',)]
    assert (recovery/'history.bundle').read_text()=='synthetic-secret-in-old-history'
    assert 'synthetic-secret' not in (output/'manifest.json').read_text()


def test_archive_uses_original_generation_and_ignores_extra_members(tmp_path):
    root=tmp_path/'repo';root.mkdir()
    database(root/'data/threat_intel.db','newer worktree observation')
    original=tmp_path/'original.db';database(original,'pre-rebase local observation')
    recovery=tmp_path/'recovery';generation=recovery/'generation-one';generation.mkdir(parents=True)
    archive=generation/'generated.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        tar.add(original,arcname='data/threat_intel.db')
        member=tarfile.TarInfo('logs/secret.log');payload=b'synthetic secret';member.size=len(payload)
        tar.addfile(member,io.BytesIO(payload))
    before=archive.read_bytes()
    output=module.prepare(recovery,tmp_path/'output',root)
    assert restored(output,tmp_path)==[('pre-rebase local observation',)]
    assert archive.read_bytes()==before


def test_archive_symlink_member_is_rejected(tmp_path):
    root=tmp_path/'repo';root.mkdir()
    generation=tmp_path/'recovery/generation-one';generation.mkdir(parents=True)
    with tarfile.open(generation/'generated.tar.gz','w:gz') as tar:
        member=tarfile.TarInfo('data/threat_intel.db');member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd'
        tar.addfile(member)
    with pytest.raises(ValueError,match='Invalid SQLite'):
        module.prepare(generation.parent,tmp_path/'out',root)


def test_external_db_symlink_is_rejected(tmp_path):
    root=tmp_path/'repo';(root/'data').mkdir(parents=True)
    outside=tmp_path/'outside.db';database(outside,'outside')
    (root/'data/threat_intel.db').symlink_to(outside)
    with pytest.raises(ValueError,match='inside checkout'):
        module.prepare(tmp_path/'recovery',tmp_path/'out',root)


def test_invalid_database_does_not_export_payload(tmp_path):
    root=tmp_path/'repo';(root/'data').mkdir(parents=True)
    (root/'data/threat_intel.db').write_text('not a database, synthetic credential')
    with pytest.raises(sqlite3.DatabaseError):
        module.prepare(tmp_path/'recovery',tmp_path/'out',root)
    assert not list((tmp_path/'out').glob('snapshot-*/*.tar.gz'))


def test_no_database_manifest_is_explicit_and_no_backups_overwritten(tmp_path):
    root=tmp_path/'repo';root.mkdir()
    first=module.prepare(tmp_path/'recovery',tmp_path/'out',root)
    second=module.prepare(tmp_path/'recovery',tmp_path/'out',root)
    assert first!=second
    assert json.loads((first/'manifest.json').read_text())['snapshots']==[]
    assert first.exists()


def notification_steps():
    workflow=yaml.safe_load((Path(__file__).parents[1]/'.github/workflows/daily.yml').read_text())
    return {s['name']:s for s in workflow['jobs']['update']['steps']}


@pytest.mark.parametrize('name',['Notify via ntfy.sh (push notification)','Alert on workflow failure'])
@pytest.mark.parametrize('mock_exit',[0,22])
def test_ntfy_http_failure_propagates_without_external_requests(tmp_path,name,mock_exit):
    step=notification_steps()[name]
    assert '--fail' in step['run'] and '--retry 2' in step['run']
    curl=tmp_path/'curl'
    curl.write_text('#!/usr/bin/env python3\nimport sys,os,json\nfrom pathlib import Path\nPath(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\nsys.exit(int(os.environ["MOCK_EXIT"]))\n')
    curl.chmod(0o755)
    capture=tmp_path/'capture.json'
    body='synthetic summary $(touch must-not-exist) `touch must-not-exist`'
    env=os.environ.copy();env.update(PATH=str(tmp_path)+os.pathsep+env['PATH'],NTFY_TOPIC='synthetic-only',NOTIFY_BODY=body,
        CAPTURE=str(capture),MOCK_EXIT=str(mock_exit),GITHUB_REPOSITORY='synthetic/repo',GITHUB_RUN_ID='42')
    script=step['run'].replace('${{ github.repository }}','synthetic/repo').replace('${{ github.run_id }}','42')
    result=subprocess.run(['bash','-e','-c',script],env=env,cwd=tmp_path,capture_output=True)
    assert result.returncode==mock_exit
    args=json.loads(capture.read_text())
    assert 'https://ntfy.sh/synthetic-only' in args
    assert not (tmp_path/'must-not-exist').exists()
    if name.startswith('Notify'):
        assert body in args and 'Priority: default' in args
    else:assert 'Priority: high' in args


def test_failure_notification_without_topic_does_not_call_curl(tmp_path):
    step=notification_steps()['Alert on workflow failure']
    env=os.environ.copy();env['NTFY_TOPIC']=''
    result=subprocess.run(['bash','-e','-c',step['run']],env=env,capture_output=True)
    assert result.returncode==0


def test_notification_and_artifact_conditions_are_preserved():
    steps=notification_steps()
    assert steps['Notify via ntfy.sh (push notification)']['if']=="${{ env.NTFY_TOPIC != '' }}"
    assert steps['Alert on workflow failure']['if']=='${{ failure() }}'
    assert steps['Prepare minimal recovery artifact']['if']=='always()'
    upload=steps['Preserve collection and publication recovery files']
    assert upload['if']=='always()'
    assert upload['with']['path'].splitlines()==[
        '${{ runner.temp }}/daily-update-artifact/snapshot-*/database-*.tar.gz',
        '${{ runner.temp }}/daily-update-artifact/snapshot-*/manifest.json']
