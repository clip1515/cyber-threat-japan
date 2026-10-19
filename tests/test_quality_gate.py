"""Fault injection is restricted to synthetic databases and temporary outputs."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

import update
from collectors.base import BaseCollector, RawItem
from database import db
from reporting import daily_report, dashboard_export


@pytest.fixture
def pipeline(tmp_path,monkeypatch):
    sources=tmp_path/'sources.yaml'
    configs=[dict(id=x,name=x,type='rss',url=f'https://example.invalid/{x}',trust_level=1,region='global') for x in ['a','b']]
    sources.write_text(yaml.safe_dump({'sources':configs}))
    monkeypatch.setattr(db,'DB_PATH',tmp_path/'data/test.db')
    monkeypatch.setattr(db,'SOURCES_YAML',sources)
    monkeypatch.setattr(update,'SOURCES_YAML',sources)
    monkeypatch.setattr(update,'LOG_DIR',tmp_path/'logs')
    monkeypatch.setattr(daily_report,'DAILY_REPORT_PATH',tmp_path/'daily.md')
    monkeypatch.setattr(daily_report,'REPORTS_DIR',tmp_path/'reports')
    monkeypatch.setattr(dashboard_export,'DASHBOARD_DATA_PATH',tmp_path/'dashboard.json')
    monkeypatch.setattr('sys.argv',['update.py'])
    monkeypatch.setenv('GITHUB_OUTPUT',str(tmp_path/'outputs'))
    db.init_db()
    with db.connection() as c:
        c.execute("INSERT INTO incidents(dedup_key,title) VALUES ('seed','Synthetic existing observation')")
    (tmp_path/'daily.md').write_text('previous report')
    (tmp_path/'dashboard.json').write_text('{"previous":true}')
    (tmp_path/'reports').mkdir()
    (tmp_path/'reports/previous.md').write_text('existing archived report')
    def run(modes=('empty','empty'),report_failure=False,json_failure=False,item_failure=False):
        class Synthetic(BaseCollector):
            def collect(self):
                mode=modes[0 if self.source_id=='a' else 1]
                if mode=='fail':raise RuntimeError('synthetic failure')
                if mode=='empty':return []
                return [RawItem(self.source_id,self.source_name,1,'Synthetic advisory',f'https://example.invalid/{self.source_id}',raw_text='synthetic')]
        monkeypatch.setattr(update,'build_collector',Synthetic)
        if report_failure:
            monkeypatch.setattr(daily_report,'generate_and_save',lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('report fault')))
        if json_failure:
            monkeypatch.setattr(dashboard_export,'generate_and_save',lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('JSON fault')))
        if item_failure:
            monkeypatch.setattr(update,'process_item',lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('item fault')))
        code=update.main()
        with db.connection() as c:
            record=dict(c.execute('SELECT * FROM run_log ORDER BY id DESC LIMIT 1').fetchone())
            assert c.execute("SELECT count(*) FROM incidents WHERE dedup_key='seed'").fetchone()[0]==1
            assert not c.execute('PRAGMA foreign_key_check').fetchall()
        assert (tmp_path/'reports/previous.md').read_text()=='existing archived report'
        return code,record,tmp_path
    return run


def previous_outputs(path):
    assert (path/'daily.md').read_text()=='previous report'
    assert (path/'dashboard.json').read_text()=='{"previous":true}'


def test_normal_empty_sources_are_successful(pipeline):
    code,run,path=pipeline()
    assert code==0
    assert (run['sources_ok'],run['sources_failed'],run['items_fetched'])==(2,0,0)
    assert '正常完了' in (path/'outputs').read_text()
    assert json.loads((path/'dashboard.json').read_text())['last_run']['id']==run['id']
    assert (path/'reports/before_run_1/0-daily.md').read_text()=='previous report'


def test_all_sources_fail_returns_nonzero_preserves_outputs(pipeline):
    code,run,path=pipeline(('fail','fail'))
    assert code==1 and (run['sources_ok'],run['sources_failed'])==(0,2)
    assert 'source_failures' in run['notes']
    assert '異常あり' in (path/'outputs').read_text()
    previous_outputs(path)


def test_partial_failure_keeps_successful_observations_without_success_status(pipeline):
    code,run,path=pipeline(('item','fail'))
    assert code==1 and (run['sources_ok'],run['sources_failed'],run['items_new'])==(1,1,1)
    assert '成功1/失敗1' in (path/'outputs').read_text()
    with db.connection() as c:assert c.execute('SELECT count(*) FROM incidents').fetchone()[0]==2
    previous_outputs(path)


@pytest.mark.parametrize('kind',['report','json'])
def test_generation_failure_never_replaces_previous_outputs(pipeline,kind):
    code,run,path=pipeline(('item','empty'),report_failure=kind=='report',json_failure=kind=='json')
    assert code==1 and f'{kind}_failed' in run['notes']
    assert run['items_new']==1
    previous_outputs(path)


def test_item_failure_is_not_a_normal_completion(pipeline):
    code,run,path=pipeline(('item','empty'),item_failure=True)
    assert code==1 and 'item_failures' in run['notes']
    previous_outputs(path)


def test_unknown_selected_source_fails(pipeline,monkeypatch):
    monkeypatch.setattr('sys.argv',['update.py','--source','missing'])
    code,run,path=pipeline()
    assert code==1 and 'no_sources_selected' in run['notes']
    previous_outputs(path)


def test_failed_write_restores_previous_outputs_and_keeps_backups(pipeline,monkeypatch):
    from reporting import publish_outputs
    actual=publish_outputs.atomic_write
    calls=[]
    def fault(path,content):
        calls.append(path)
        if len(calls)==2:raise OSError('synthetic disk failure')
        actual(path,content)
    monkeypatch.setattr(publish_outputs,'atomic_write',fault)
    code,run,path=pipeline()
    assert code==1 and 'output_publish_failed' in run['notes']
    previous_outputs(path)
    assert (path/'reports/before_run_1/0-daily.md').read_text()=='previous report'


def test_failure_notification_carries_collection_counts_without_changing_conditions():
    workflow=yaml.safe_load((Path(__file__).parents[1]/'.github/workflows/daily.yml').read_text())
    steps={s['name']:s for s in workflow['jobs']['update']['steps']}
    assert steps['Run collection pipeline (update.py)']['id']=='collection'
    assert steps['Alert on workflow failure']['if']=='${{ failure() }}'
    assert 'COLLECTION_SUMMARY' in steps['Alert on workflow failure']['env']
    assert steps['Notify via ntfy.sh (push notification)']['if']=="${{ env.NTFY_TOPIC != '' }}"


def test_json_from_another_run_is_not_published(pipeline,monkeypatch):
    def stale(conn,run_id=None):
        dashboard_export.DASHBOARD_DATA_PATH.write_text(json.dumps({'last_run':{'id':999}}))
        return dashboard_export.DASHBOARD_DATA_PATH
    monkeypatch.setattr(dashboard_export,'generate_and_save',stale)
    code,run,path=pipeline()
    assert code==1 and 'output_publish_failed' in run['notes']
    previous_outputs(path)


@pytest.mark.parametrize('mode,expected',[('empty',0),('fail',1)])
def test_actual_cli_exit_status_is_quality_gate(tmp_path,mode,expected):
    import subprocess,sys,os
    script=r'''
import sys,runpy
from pathlib import Path
sys.path.insert(0,sys.argv[1])
case=Path(sys.argv[2]);mode=sys.argv[3]
import config.settings as s
s.BASE_DIR=case;s.DATA_DIR=case/'data';s.DB_PATH=case/'data/test.db'
s.LOG_DIR=case/'logs';s.REPORTS_DIR=case/'reports';s.DAILY_REPORT_PATH=case/'daily.md';s.SOURCES_YAML=case/'sources.yaml'
s.SOURCES_YAML.write_text('sources:\n  - id: synthetic\n    name: Synthetic\n    type: rss\n    url: https://example.invalid/feed\n    trust_level: 1\n')
import collectors
from collectors.base import BaseCollector
class Synthetic(BaseCollector):
    def collect(self):
        if mode=='fail':raise RuntimeError('synthetic failure')
        return []
collectors.build_collector=Synthetic
entry=Path(sys.argv[1])/'update.py';sys.argv=['update.py']
runpy.run_path(str(entry),run_name='__main__')
'''
    env=os.environ.copy();env.pop('GITHUB_OUTPUT',None)
    result=subprocess.run([sys.executable,'-c',script,str(Path(__file__).parents[1]),str(tmp_path),mode],capture_output=True,text=True,env=env)
    assert result.returncode==expected,result.stderr


def test_html_error_page_is_not_a_normal_empty_rss():
    from collectors.rss_collector import RssCollector
    from types import SimpleNamespace
    collector=RssCollector(dict(id='synthetic',name='Synthetic',trust_level=1,url='https://example.invalid/feed'))
    with patch('collectors.rss_collector.http_get',return_value=SimpleNamespace(content=b'<html>service error</html>')):
        assert collector.safe_collect()==[]
    assert collector.last_collection_succeeded is False


def test_recognized_empty_rss_is_normal_success():
    from collectors.rss_collector import RssCollector
    from types import SimpleNamespace
    collector=RssCollector(dict(id='synthetic',name='Synthetic',trust_level=1,url='https://example.invalid/feed'))
    body=b'<rss version="2.0"><channel><title>Synthetic empty feed</title><link>https://example.invalid</link><description>Empty</description></channel></rss>'
    with patch('collectors.rss_collector.http_get',return_value=SimpleNamespace(content=body)):
        assert collector.safe_collect()==[]
    assert collector.last_collection_succeeded is True


def test_repeated_normal_runs_preserve_all_previous_output_backups(pipeline):
    code,first,path=pipeline()
    assert code==0
    original=(path/'reports/before_run_1/0-daily.md').read_bytes()
    previous_daily=(path/'daily.md').read_bytes()
    code,second,path=pipeline()
    assert code==0 and second['id']!=first['id']
    assert (path/'reports/before_run_1/0-daily.md').read_bytes()==original
    assert (path/'reports/before_run_2/0-daily.md').read_bytes()==previous_daily
