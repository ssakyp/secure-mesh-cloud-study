package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// verifier validates RS256 JWTs using only the standard library.
// It is deliberately strict: only RS256 is accepted (blocks alg=none and
// HS256 key-confusion), exp is mandatory, iss/aud are enforced when configured.
type verifier struct {
	pub  *rsa.PublicKey
	iss  string
	aud  string
	skew time.Duration
}

func newVerifierFromPEMFile(path, iss, aud string) (*verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("no PEM block in public key file")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return &verifier{pub: pub, iss: iss, aud: aud, skew: 30 * time.Second}, nil
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func (v *verifier) checkHeader(h string, now time.Time) error {
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return errors.New("missing bearer token")
	}
	return v.verify(strings.TrimPrefix(h, p), now)
}

func (v *verifier) verify(tok string, now time.Time) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("malformed token")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return errors.New("bad header encoding")
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return errors.New("bad header json")
	}
	if hdr.Alg != "RS256" {
		return fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return errors.New("bad signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(v.pub, crypto.SHA256, digest[:], sig); err != nil {
		return errors.New("bad signature")
	}
	pb, err := b64(parts[1])
	if err != nil {
		return errors.New("bad payload encoding")
	}
	var c struct {
		Iss string          `json:"iss"`
		Aud json.RawMessage `json:"aud"`
		Exp *float64        `json:"exp"`
		Nbf *float64        `json:"nbf"`
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return errors.New("bad payload json")
	}
	if c.Exp == nil {
		return errors.New("exp missing")
	}
	if now.After(time.Unix(int64(*c.Exp), 0).Add(v.skew)) {
		return errors.New("token expired")
	}
	if c.Nbf != nil && now.Add(v.skew).Before(time.Unix(int64(*c.Nbf), 0)) {
		return errors.New("token not yet valid")
	}
	if v.iss != "" && c.Iss != v.iss {
		return errors.New("wrong issuer")
	}
	if v.aud != "" && !audContains(c.Aud, v.aud) {
		return errors.New("wrong audience")
	}
	return nil
}

func audContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}
