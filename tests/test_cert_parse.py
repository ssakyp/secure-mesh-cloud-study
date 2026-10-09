#!/usr/bin/env python3
"""Unit test for the certificate-validity decoding used by the cert-rotation observation (E3)
and for its summary. Uses a locally generated certificate shaped like an istioctl SDS entry."""
import base64, datetime as dt, pathlib, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts")); sys.path.insert(0, str(ROOT / "analysis"))
import run_resilience, resilience


def mk(nb, na):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workload")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


now = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.timezone.utc)
events = []
for i, off in enumerate([0, 30, 70]):     # rotation between sample 2 and 3: new, later expiry
    nb = now + dt.timedelta(minutes=off if off < 60 else 60)
    pem = mk(nb.replace(tzinfo=None), (nb + dt.timedelta(minutes=30)).replace(tzinfo=None))
    sec = {"name": "default", "versionInfo": str(i), "secret": {"tlsCertificate": {"certificateChain": {"inlineBytes": base64.b64encode(pem).decode()}}}}
    a, b = run_resilience.cert_validity(sec)
    events.append({"t": i, "event": "cert_seen", "not_before": a, "not_after": b})
s = resilience.cert_summary(events)
print(s)
assert s["cert_lifetime_s"] == 1800 and s["cert_rotations_observed"] == 2 and s["cert_samples"] == 3, s
print("RESULT: PASS")
