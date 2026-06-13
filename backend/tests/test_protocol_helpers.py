"""Coverage for pure protocol helpers (MSCA request-id parsing, SCEP PKCS#7)."""
import pytest


class TestMscaRequestIdExtraction:
    def _extract(self, msg):
        from services.msca.requests import MicrosoftCARequestsMixin
        return MicrosoftCARequestsMixin._extract_request_id(msg)

    def test_request_id_keyword(self):
        assert self._extract('Certificate request id: 4711 is pending') == 4711

    def test_request_hash_form(self):
        assert self._extract('Taken under submission (request #88)') == 88

    def test_bare_number_fallback(self):
        assert self._extract('disposition 12345') == 12345

    def test_no_number_returns_none(self):
        assert self._extract('Request is pending manager approval') is None


class TestScepDegeneratePkcs7:
    def test_wraps_single_cert(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs7
        from datetime import datetime, timedelta, timezone
        from services.scep.crypto_helpers import create_degenerate_pkcs7

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Deg P7 CA')])
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
                .sign(key, hashes.SHA256()))

        der = create_degenerate_pkcs7([cert])
        assert isinstance(der, (bytes, bytearray)) and len(der) > 0
        # Must round-trip as a certs-only PKCS#7 containing our cert
        certs = pkcs7.load_der_pkcs7_certificates(der)
        assert any(c.serial_number == cert.serial_number for c in certs)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
