"""Reads the agent's own identity from its client certificate."""
from cryptography import x509
from cryptography.x509.oid import NameOID


def cert_common_name(cert_path):
    """Return the Common Name (CN) of a PEM-encoded certificate."""
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise ValueError(f"certificate {cert_path} has no Common Name")
    return attrs[0].value
