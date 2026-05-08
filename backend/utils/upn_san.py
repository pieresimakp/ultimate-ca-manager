"""UPN SAN encoding for x509.OtherName.

Microsoft UPN OID: 1.3.6.1.4.1.311.20.2.3
Value: DER-encoded UTF8String wrapped in x509.OtherName.

Used for smartcard logon, Kerberos PKINIT, and ADCS enrollment scenarios.
The companion parser lives in utils/cert_extensions.py:_parse_san (OtherName branch).
"""
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from asn1crypto.core import UTF8String

UPN_OID = ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')


def build_upn_other_name(upn):
    """Build a SAN OtherName entry for a Microsoft UPN.

    Args:
        upn: User Principal Name like 'user@corp.local'.

    Returns:
        x509.OtherName ready to add to SubjectAlternativeName().

    Raises:
        ValueError if upn is empty or doesn't contain exactly one '@' with non-empty halves.
    """
    if not upn or not isinstance(upn, str):
        raise ValueError(f"Invalid UPN: {upn!r} (must be non-empty string)")
    upn = upn.strip()
    parts = upn.split('@')
    if len(parts) != 2 or not all(parts):
        raise ValueError(f"Invalid UPN: {upn!r} (must be user@domain)")
    der = UTF8String(upn).dump()
    return x509.OtherName(UPN_OID, der)


def is_valid_upn(value):
    """Loose UPN validation: non-empty string, exactly one '@', non-empty halves."""
    if not value or not isinstance(value, str):
        return False
    parts = value.strip().split('@')
    return len(parts) == 2 and all(parts)


def extract_upns_from_san_list(san_list):
    """Extract UPN strings from a list of x509 SAN entries.

    Walks OtherName entries, decodes UTF8String for those matching UPN_OID.
    Returns list of UPN strings (may be empty). Silently skips malformed entries.
    """
    upns = []
    for entry in san_list or []:
        if not isinstance(entry, x509.OtherName):
            continue
        if entry.type_id != UPN_OID:
            continue
        try:
            decoded = UTF8String.load(entry.value).native
            if decoded:
                upns.append(decoded)
        except Exception:
            continue
    return upns
