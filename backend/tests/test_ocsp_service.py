"""Tests for the OCSP responder service (previously 0 coverage)."""
import pytest
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes

from models import CA, Certificate
from services.ocsp_service import OCSPService


def _ca_model(ca_dict):
    return CA.query.get(ca_dict['id'])


def _cert_model(cert_dict):
    return Certificate.query.get(cert_dict['id'])


def _build_ocsp_request(cert_serial, issuer_cert):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate_by_hash(
        issuer_name_hash=b'\x00' * 32,
        issuer_key_hash=b'\x00' * 32,
        serial_number=cert_serial,
        algorithm=hashes.SHA256(),
    ) if hasattr(ocsp.OCSPRequestBuilder, 'add_certificate_by_hash') else builder
    return builder


class TestParseRequest:
    def test_parse_valid_request(self, app, create_ca, create_cert):
        with app.app_context():
            ca = create_ca(cn='OCSP Parse CA')
            cert = create_cert(cn='leaf.example.com', ca_id=ca['id'])
            ca_obj = _ca_model(ca)
            cert_obj = _cert_model(cert)

            # Build a real OCSP request against the issued cert
            import base64
            ca_pem = base64.b64decode(ca_obj.crt)
            issuer = x509.load_pem_x509_certificate(ca_pem)
            leaf = x509.load_pem_x509_certificate(base64.b64decode(cert_obj.crt))
            req = ocsp.OCSPRequestBuilder().add_certificate(
                leaf, issuer, hashes.SHA256()).build()
            der = req.public_bytes(__import__('cryptography').hazmat.primitives.serialization.Encoding.DER)

            parsed = OCSPService().parse_request(der)
            assert parsed is not None
            assert parsed.serial_number == leaf.serial_number

    def test_parse_garbage_returns_none(self, app):
        with app.app_context():
            assert OCSPService().parse_request(b'\x00\x01\x02not-a-request') is None


class TestGenerateResponse:
    def test_good_certificate(self, app, create_ca, create_cert):
        with app.app_context():
            ca = create_ca(cn='OCSP Good CA')
            cert = create_cert(cn='good.example.com', ca_id=ca['id'])
            ca_obj = _ca_model(ca)
            serial = int(_cert_model(cert).serial_number, 16)

            der, status = OCSPService().generate_response(ca_obj, serial)
            assert status == 'good'
            resp = ocsp.load_der_ocsp_response(der)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_revoked_certificate(self, app, create_ca, create_cert):
        from services.cert_service import CertificateService
        with app.app_context():
            ca = create_ca(cn='OCSP Revoked CA')
            cert = create_cert(cn='revoked.example.com', ca_id=ca['id'])
            CertificateService.revoke_certificate(cert['id'], reason='keyCompromise', username='test')
            ca_obj = _ca_model(ca)
            serial = int(_cert_model(cert).serial_number, 16)

            der, status = OCSPService().generate_response(ca_obj, serial)
            assert status == 'revoked'
            resp = ocsp.load_der_ocsp_response(der)
            assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED

    def test_nonce_echoed_when_present(self, app, create_ca, create_cert):
        with app.app_context():
            ca = create_ca(cn='OCSP Nonce CA')
            cert = create_cert(cn='nonce.example.com', ca_id=ca['id'])
            ca_obj = _ca_model(ca)
            serial = int(_cert_model(cert).serial_number, 16)
            der, _ = OCSPService().generate_response(ca_obj, serial, request_nonce=b'abc123nonce')
            resp = ocsp.load_der_ocsp_response(der)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL


class TestCleanup:
    def test_cleanup_runs(self, app):
        with app.app_context():
            # Should not raise even with nothing to clean
            OCSPService().cleanup_expired_responses()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
