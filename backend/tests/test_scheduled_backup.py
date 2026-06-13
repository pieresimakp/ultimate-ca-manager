"""Tests for scheduled backups (previously a stub: schedule PATCH was a no-op,
history was hardcoded, no scheduler task). Source of truth = the General
settings the UI writes (auto_backup_enabled / backup_frequency /
backup_retention_days / backup_password)."""
import json
from datetime import timedelta
import pytest

from models import db, SystemConfig
from utils.datetime_utils import utc_now, utc_isoformat


def _set(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.session.add(SystemConfig(key=key, value=value))
    db.session.commit()


class TestScheduleReadsGeneralSettings:
    def test_get_schedule_reflects_general_keys(self, app):
        with app.app_context():
            from services.backup.schedule import get_schedule
            _set('auto_backup_enabled', 'true')
            _set('backup_frequency', 'weekly')
            _set('backup_retention_days', '14')
            sched = get_schedule()
            assert sched['enabled'] is True
            assert sched['frequency'] == 'weekly'
            assert sched['retention_days'] == 14

    def test_disabled_when_flag_false(self, app):
        with app.app_context():
            from services.backup.schedule import get_schedule
            _set('auto_backup_enabled', 'false')
            assert get_schedule()['enabled'] is False


class TestDueLogic:
    def test_due_when_never_run(self, app):
        with app.app_context():
            from services.backup.schedule import _is_due
            assert _is_due({'frequency': 'daily', 'last_run': None}, utc_now()) is True

    def test_not_due_within_period(self, app):
        with app.app_context():
            from services.backup.schedule import _is_due
            recent = utc_isoformat(utc_now() - timedelta(hours=1))
            assert _is_due({'frequency': 'daily', 'last_run': recent}, utc_now()) is False

    def test_due_after_period(self, app):
        with app.app_context():
            from services.backup.schedule import _is_due
            old = utc_isoformat(utc_now() - timedelta(days=2))
            assert _is_due({'frequency': 'daily', 'last_run': old}, utc_now()) is True

    def test_weekly_not_due_after_two_days(self, app):
        with app.app_context():
            from services.backup.schedule import _is_due
            two_days = utc_isoformat(utc_now() - timedelta(days=2))
            assert _is_due({'frequency': 'weekly', 'last_run': two_days}, utc_now()) is False


class TestScheduledTaskGating:
    def test_disabled_is_noop(self, app, monkeypatch):
        with app.app_context():
            from services.backup import schedule
            _set('auto_backup_enabled', 'false')
            called = []
            monkeypatch.setattr('services.backup_service.BackupService.create_backup',
                                lambda self, pw, **k: called.append(1) or b'x')
            schedule.run_scheduled_backup()
            assert called == []

    def test_enabled_but_no_password_is_noop(self, app, monkeypatch):
        with app.app_context():
            from services.backup import schedule
            _set('auto_backup_enabled', 'true')
            _set('backup_frequency', 'daily')
            SystemConfig.query.filter_by(key='backup_password').delete()
            SystemConfig.query.filter_by(key='backup.last_run').delete()
            db.session.commit()
            called = []
            monkeypatch.setattr('services.backup_service.BackupService.create_backup',
                                lambda self, pw, **k: called.append(1) or b'x')
            schedule.run_scheduled_backup()
            assert called == []  # no password → skip


class TestScheduleEndpoints:
    def test_patch_persists_to_general_and_get_reflects(self, auth_client):
        r = auth_client.patch('/api/v2/settings/backup/schedule',
                              data=json.dumps({'enabled': True, 'frequency': 'monthly',
                                               'retention_days': 7}),
                              content_type='application/json')
        assert r.status_code == 200
        data = json.loads(r.data)['data']
        assert data['enabled'] is True and data['frequency'] == 'monthly'
        assert data['retention_days'] == 7
        # cleanup
        auth_client.patch('/api/v2/settings/backup/schedule',
                          data=json.dumps({'enabled': False}),
                          content_type='application/json')

    def test_history_not_hardcoded_fake(self, auth_client):
        r = auth_client.get('/api/v2/settings/backup/history')
        assert r.status_code == 200
        items = json.loads(r.data)['data']
        assert not any(b.get('filename', '').endswith('.tar.gz') for b in items)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
