"""Stage both outputs before publication; retain previous output versions."""
import json
import logging
import os
from pathlib import Path
import tempfile

logger = logging.getLogger('update')


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.pending-', delete=False) as f:
        pending = Path(f.name)
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(pending, path)


def generate_outputs(conn, run_id, run_meta):
    from reporting import daily_report as report, dashboard_export as dashboard
    originals = report.DAILY_REPORT_PATH, report.REPORTS_DIR, dashboard.DASHBOARD_DATA_PATH
    errors = []
    with tempfile.TemporaryDirectory(prefix='threat-output-') as scratch:
        scratch = Path(scratch)
        report.DAILY_REPORT_PATH = scratch / 'daily.md'
        report.REPORTS_DIR = scratch / 'reports'
        dashboard.DASHBOARD_DATA_PATH = scratch / 'dashboard.json'
        try:
            try:
                report.generate_and_save(conn, run_id, run_meta)
            except Exception:
                logger.exception('Report generation failed; existing outputs retained')
                errors.append('report_failed')
            try:
                dashboard.generate_and_save(conn, run_id=run_id)
            except Exception:
                logger.exception('JSON generation failed; existing outputs retained')
                errors.append('json_failed')
        finally:
            report.DAILY_REPORT_PATH, report.REPORTS_DIR, dashboard.DASHBOARD_DATA_PATH = originals
        if errors:
            return errors
        try:
            data = json.loads((scratch / 'dashboard.json').read_text())
            if not data.get('last_run') or data['last_run']['id'] != run_id:
                raise ValueError('JSON does not describe the current run')
            outputs = [(originals[0], (scratch / 'daily.md').read_bytes()),
                       (originals[2], (scratch / 'dashboard.json').read_bytes())]
            for staged in (scratch / 'reports').glob('*.md'):
                target = originals[1] / staged.name
                if target.exists():
                    raise FileExistsError('Refusing to overwrite an existing archived report')
                outputs.append((target, staged.read_bytes()))
            # Keep previous daily/JSON permanently in a new run-specific backup.
            backup = originals[1] / f'before_run_{run_id}'
            backup.mkdir(parents=True, exist_ok=False)
            previous = []
            for index, (target, _) in enumerate(outputs):
                if target.exists():
                    content = target.read_bytes()
                    (backup / f'{index}-{target.name}').write_bytes(content)
                    previous.append((target, content))
            try:
                for target, content in outputs:
                    atomic_write(target, content)
            except Exception:
                for target, content in previous:
                    atomic_write(target, content)
                raise
        except Exception:
            logger.exception('Output publication failed; previous versions retained in reports backups')
            return ['output_publish_failed']
    return []
