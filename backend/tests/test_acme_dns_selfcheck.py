"""DNS-01 self-check before submitting to the CA (#140)."""
import sys
import types
import pytest

from api.v2.acme_client import orders as orders_mod


@pytest.fixture
def fake_dns(monkeypatch):
    """Install a fake dns.resolver whose TXT answers are controllable."""
    state = {'records': {}}  # name -> list[str]

    class _RData:
        def __init__(self, values):
            self.strings = [v.encode() for v in values]

    def resolve(name, rtype, lifetime=None):
        vals = state['records'].get(name)
        if not vals:
            raise Exception('NXDOMAIN')
        return [_RData(vals)]

    fake_resolver = types.SimpleNamespace(resolve=resolve)
    fake_dns_mod = types.ModuleType('dns')
    fake_resolver_mod = types.ModuleType('dns.resolver')
    fake_resolver_mod.resolve = resolve
    fake_dns_mod.resolver = fake_resolver_mod
    monkeypatch.setitem(sys.modules, 'dns', fake_dns_mod)
    monkeypatch.setitem(sys.modules, 'dns.resolver', fake_resolver_mod)
    return state


def test_txt_present_true_when_value_matches(fake_dns):
    fake_dns['records']['_acme-challenge.example.com'] = ['other', 'the-token']
    assert orders_mod._txt_present('_acme-challenge.example.com', 'the-token') is True


def test_txt_present_false_when_absent(fake_dns):
    assert orders_mod._txt_present('_acme-challenge.example.com', 'the-token') is False


def test_selfcheck_ok_when_all_present(fake_dns):
    fake_dns['records']['_acme-challenge.a.com'] = ['ta']
    fake_dns['records']['_acme-challenge.b.com'] = ['tb']
    ch = {
        'a.com': {'dns_txt_name': '_acme-challenge.a.com', 'dns_txt_value': 'ta'},
        'b.com': {'dns_txt_name': '_acme-challenge.b.com', 'dns_txt_value': 'tb'},
    }
    res = orders_mod._dns_selfcheck(ch, timeout=0)
    assert res['ok'] is True and res['missing'] == []


def test_selfcheck_reports_missing(fake_dns):
    fake_dns['records']['_acme-challenge.a.com'] = ['ta']
    ch = {
        'a.com': {'dns_txt_name': '_acme-challenge.a.com', 'dns_txt_value': 'ta'},
        'b.com': {'dns_txt_name': '_acme-challenge.b.com', 'dns_txt_value': 'tb'},
    }
    res = orders_mod._dns_selfcheck(ch, timeout=0)
    assert res['ok'] is False and res['missing'] == ['b.com']


def test_selfcheck_ignores_non_dns_challenges(fake_dns):
    ch = {'a.com': {'dns_txt_name': None, 'dns_txt_value': None}}  # http-01
    res = orders_mod._dns_selfcheck(ch, timeout=0)
    assert res['ok'] is True and res['missing'] == []


def test_auto_path_honors_full_configured_timeout(monkeypatch):
    """The auto-poll self-check runs in a BACKGROUND thread now, so it is no
    longer bounded by the gunicorn worker timeout and must honor the full
    configured value (up to 3600s). Regression guard for #140: a long timeout
    must NOT be silently capped."""
    monkeypatch.setattr(orders_mod, '_dns_propagation_timeout', lambda: 3600)
    assert orders_mod._dns_propagation_timeout() == 3600


def test_auto_poll_runs_inline_under_testing(app, monkeypatch):
    """Under TESTING the auto-poll MUST run inline (the test DB uses a single
    shared SQLite connection that a background thread would contend with), and
    must NOT spawn a real thread."""
    import threading as real_threading

    started = []
    real_thread_class = real_threading.Thread

    class _SpyThread(real_thread_class):
        def start(self):
            started.append(True)

    monkeypatch.setattr(orders_mod.threading, 'Thread', _SpyThread)
    with app.test_request_context():
        app.config['TESTING'] = True
        # Order 999999 doesn't exist → worker returns early, no exception.
        orders_mod._run_auto_poll_background(999999, 'staging')
    assert started == [], 'background thread must NOT be spawned under TESTING'


def test_auto_poll_spawns_thread_when_not_testing(app, monkeypatch):
    """Outside TESTING the auto-poll launches a daemon thread (the request must
    return immediately while DNS validation runs in the background)."""
    started = []

    class _SpyThread:
        def __init__(self, *a, **k):
            pass
        def start(self):
            started.append(True)

    monkeypatch.setattr(orders_mod.threading, 'Thread', _SpyThread)
    with app.test_request_context():
        app.config['TESTING'] = False
        orders_mod._run_auto_poll_background(999999, 'staging')
    assert started == [True], 'a background thread must be spawned outside TESTING'
