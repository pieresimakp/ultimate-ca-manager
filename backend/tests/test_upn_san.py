"""Tests for utils.upn_san — UPN SAN encoding helper."""
import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from utils.upn_san import build_upn_other_name, is_valid_upn, UPN_OID
from utils.cert_extensions import _parse_san


def test_build_upn_other_name_returns_x509_othername():
    on = build_upn_other_name('alice@corp.local')
    assert isinstance(on, x509.OtherName)
    assert on.type_id == UPN_OID


def test_build_upn_other_name_strips_whitespace():
    on = build_upn_other_name('  alice@corp.local  ')
    # Round-trip: parse back and check value
    from asn1crypto.core import UTF8String
    assert UTF8String.load(on.value).native == 'alice@corp.local'


@pytest.mark.parametrize('bad', ['', '   ', 'no-at-sign', '@only', 'only@', 'two@@signs', None, 123, []])
def test_build_upn_other_name_rejects_invalid(bad):
    with pytest.raises((ValueError, TypeError, AttributeError)):
        build_upn_other_name(bad)


def test_round_trip_in_san_extension():
    """Build SAN ext with UPN, parse it back, confirm value preserved."""
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test')])
    san = x509.SubjectAlternativeName([
        x509.DNSName('test.local'),
        build_upn_other_name('bob@corp.local'),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256()))

    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    parsed = _parse_san(ext.value)
    assert any(e.get('type') == 'UPN' and e.get('value') == 'bob@corp.local' for e in parsed)


def test_is_valid_upn_accepts_valid():
    assert is_valid_upn('a@b.c')
    assert is_valid_upn('alice@corp.local')
    assert is_valid_upn('  trim.me@example.org  ')


@pytest.mark.parametrize('bad', ['', '   ', 'no-at', '@only', 'only@', 'a@@b', None, 123, []])
def test_is_valid_upn_rejects_invalid(bad):
    assert not is_valid_upn(bad)
