"""Tests for the RFC 3161 Time-Stamp Authority service (previously 0 coverage)."""
import hashlib
import pytest

from asn1crypto import tsp, algos, core


def _status_native(resp_der):
    """Return the PKIStatus of a TimeStampResp, tolerating status-only
    (token-less) rejection responses that asn1crypto won't fully load."""
    try:
        return tsp.TimeStampResp.load(resp_der)['status']['status'].native
    except ValueError:
        # Status-only response: SEQUENCE { PKIStatusInfo }
        inner = core.Sequence.load(resp_der).contents
        return tsp.PKIStatusInfo.load(inner)['status'].native


def _self_signed_tsa():
    """Build a self-signed cert + key suitable for the TSA service."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test TSA')])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def _build_tsq(digest: bytes, hash_oid='2.16.840.1.101.3.4.2.1'):
    """Build a DER TimeStampReq for the given SHA-256 digest."""
    req = tsp.TimeStampReq({
        'version': 1,
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': hash_oid}),
            'hashed_message': digest,
        }),
        'cert_req': True,
    })
    return req.dump()


class TestProcessRequest:
    def test_valid_request_granted(self):
        from services.tsa_service import TSAService
        cert, key = _self_signed_tsa()
        svc = TSAService(cert, key, policy_oid='1.2.3.4.1')

        digest = hashlib.sha256(b'hello world').digest()
        resp_der, http = svc.process_request(_build_tsq(digest))
        assert http == 200
        resp = tsp.TimeStampResp.load(resp_der)
        status = resp['status']['status'].native
        assert status in ('granted', 'granted_with_mods')
        # A granted response must carry a timeStampToken
        assert resp['time_stamp_token'].native is not None

    def test_malformed_request_rejected(self):
        from services.tsa_service import TSAService
        cert, key = _self_signed_tsa()
        svc = TSAService(cert, key)
        resp_der, http = svc.process_request(b'\x30\x03not-a-tsq')
        assert http == 200
        assert _status_native(resp_der) == 'rejection'

    def test_unsupported_hash_rejected(self):
        from services.tsa_service import TSAService
        cert, key = _self_signed_tsa()
        svc = TSAService(cert, key)
        # MD5 OID — not in the allowed set
        tsq = _build_tsq(b'\x00' * 16, hash_oid='1.2.840.113549.2.5')
        resp_der, http = svc.process_request(tsq)
        assert _status_native(resp_der) == 'rejection'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
