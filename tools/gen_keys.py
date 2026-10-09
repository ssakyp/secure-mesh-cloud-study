#!/usr/bin/env python3
"""Generate the study's JWT key pair, inline JWKS and (valid + attack) tokens.
Private material stays in ./keys (git-ignored). Tokens are hand-built so that
deliberately invalid variants (alg=none, HS256 key confusion, tampering) are possible."""
import base64, hashlib, hmac, json, pathlib, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
ISS, AUD = "mesh-study", "mesh-api"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jenc(o):
    return b64(json.dumps(o, separators=(",", ":")).encode())


def uint_b64(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def rs256(key, hdr, claims):
    si = f"{jenc(hdr)}.{jenc(claims)}"
    sig = key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{si}.{b64(sig)}"


def main():
    (KEYS / "tokens").mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (KEYS / "jwt_private.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (KEYS / "jwt_public.pem").write_bytes(pub_pem)
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "study-1", "n": uint_b64(nums.n), "e": uint_b64(nums.e)}]}
    (KEYS / "jwks.json").write_text(json.dumps(jwks))

    now = int(time.time())
    hdr = {"alg": "RS256", "typ": "JWT", "kid": "study-1"}
    ok = {"iss": ISS, "aud": AUD, "sub": "user-1", "iat": now, "exp": now + 30 * 86400}
    tokens = {
        "valid": rs256(key, hdr, ok),
        "expired": rs256(key, hdr, {**ok, "exp": now - 3600}),
        "wrong_aud": rs256(key, hdr, {**ok, "aud": "other-api"}),
        "wrong_iss": rs256(key, hdr, {**ok, "iss": "evil-issuer"}),
        "wrong_key": rs256(other, hdr, ok),
        "nbf_future": rs256(key, hdr, {**ok, "nbf": now + 3600}),
    }
    v = tokens["valid"].split(".")
    tokens["tampered"] = f"{v[0]}.{jenc({**ok, 'sub': 'admin'})}.{v[2]}"       # payload swapped after signing
    tokens["alg_none"] = f"{jenc({'alg': 'none', 'typ': 'JWT'})}.{jenc(ok)}."
    si = f"{jenc({'alg': 'HS256', 'typ': 'JWT'})}.{jenc(ok)}"                   # key-confusion: HMAC with the public key
    tokens["hs256_confusion"] = f"{si}.{b64(hmac.new(pub_pem, si.encode(), hashlib.sha256).digest())}"
    for name, tok in tokens.items():
        (KEYS / "tokens" / f"{name}.jwt").write_text(tok)
    print(f"wrote keys + {len(tokens)} tokens to {KEYS}")


if __name__ == "__main__":
    main()
