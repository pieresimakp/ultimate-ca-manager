"""Regression tests for protocol-endpoint signing guards (lot-4 review).

  - TSA (/tsa): refuses to sign when no TSA CA is explicitly configured
    (no silent fallback to an arbitrary CA key) and when the configured CA
    is offline.
  - SCEP auto-approve: refuses to issue a certificate when the CA is offline,
    consistent with the CSR/CRL/EST signing paths.
"""
import json
import pytest

from models import db, CA
from models.system_config import SystemConfig


def _set_config(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.session.add(SystemConfig(key=key, value=value))
    db.session.commit()


def _clear_config(key):
    row = SystemConfig.query.filter_by(key=key).first()
    if row:
        db.session.delete(row)
        db.session.commit()


class TestTsaConfigGuard:
    """TSA must be an explicit opt-in; no signing with an arbitrary CA."""

    def test_tsa_unconfigured_returns_503(self, app, client):
        with app.app_context():
            _clear_config('tsa_ca_refid')
        # A minimal but well-formed-enough body; we must get 503 *before*
        # any CA key is selected, regardless of payload.
        r = client.post('/tsa', data=b'\x30\x03\x02\x01\x01',
                        content_type='application/timestamp-query')
        assert r.status_code == 503
        assert b'not configured' in r.data.lower()

    def test_tsa_offline_ca_returns_503(self, app, client, create_ca):
        ca = create_ca(cn='TSA Offline CA')
        with app.app_context():
            ca_obj = CA.query.get(ca['id'])
            ca_obj.offline = True
            ca_obj.offline_reason = 'test'
            db.session.commit()
            _set_config('tsa_ca_refid', ca_obj.refid)
        try:
            r = client.post('/tsa', data=b'\x30\x03\x02\x01\x01',
                            content_type='application/timestamp-query')
            assert r.status_code == 503
            assert b'unavailable' in r.data.lower()
        finally:
            with app.app_context():
                _clear_config('tsa_ca_refid')


class TestScepOfflineGuard:
    """SCEP auto-approve must not sign with an offline CA."""

    def test_auto_approve_refuses_offline_ca(self, app, create_ca):
        ca = create_ca(cn='SCEP Offline CA')
        with app.app_context():
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            from services.scep.scep_service import SCEPService

            ca_obj = CA.query.get(ca['id'])
            ca_obj.offline = True
            ca_obj.offline_reason = 'maintenance'
            db.session.commit()

            svc = SCEPService(ca_refid=ca_obj.refid, auto_approve=True)

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.example.com')]))
                .sign(key, hashes.SHA256())
            )

            class _Req:
                id = 1
            with pytest.raises(ValueError, match='offline'):
                svc._auto_approve_request(_Req(), csr)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
