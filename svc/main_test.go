package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enc(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(t *testing.T, key *rsa.PrivateKey, hdr, claims map[string]any) string {
	h, p := enc(hdr), enc(claims)
	d := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writePub(t *testing.T, key *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	f := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVerifier(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	v, err := newVerifierFromPEMFile(writePub(t, key), "mesh-study", "mesh-api")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	hdr := map[string]any{"alg": "RS256", "typ": "JWT"}
	ok := map[string]any{"iss": "mesh-study", "aud": "mesh-api", "exp": now.Add(time.Hour).Unix()}
	mod := func(k string, val any) map[string]any {
		c := map[string]any{}
		for a, b := range ok {
			c[a] = b
		}
		c[k] = val
		return c
	}
	valid := sign(t, key, hdr, ok)
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + enc(mod("aud", "other")) + "." + parts[2] // payload swapped after signing
	cases := []struct {
		name string
		tok  string
		want bool
	}{
		{"valid", valid, true},
		{"expired", sign(t, key, hdr, mod("exp", now.Add(-time.Hour).Unix())), false},
		{"wrong_aud", sign(t, key, hdr, mod("aud", "x")), false},
		{"aud_array_ok", sign(t, key, hdr, mod("aud", []string{"a", "mesh-api"})), true},
		{"wrong_iss", sign(t, key, hdr, mod("iss", "evil")), false},
		{"wrong_key", sign(t, other, hdr, ok), false},
		{"nbf_future", sign(t, key, hdr, mod("nbf", now.Add(time.Hour).Unix())), false},
		{"no_exp", sign(t, key, hdr, map[string]any{"iss": "mesh-study", "aud": "mesh-api"}), false},
		{"tampered_payload", tampered, false},
		{"alg_none", enc(map[string]any{"alg": "none"}) + "." + enc(ok) + ".", false},
		{"hs256_confusion", enc(map[string]any{"alg": "HS256"}) + "." + enc(ok) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig")), false},
		{"garbage", "not.a.jwt", false},
	}
	for _, c := range cases {
		err := v.verify(c.tok, now)
		if (err == nil) != c.want {
			t.Errorf("%s: want ok=%v got err=%v", c.name, c.want, err)
		}
	}
	if err := v.checkHeader("", now); err == nil {
		t.Error("missing header must fail")
	}
}

func TestChainPropagatesAndStatus(t *testing.T) {
	leaf := newServer(config{Name: "account", PayloadBytes: 512, CPUIters: 1, Routes: map[string]route{"/c2": {}}}, nil)
	ts1 := httptest.NewServer(http.HandlerFunc(leaf.handle))
	defer ts1.Close()
	mid := newServer(config{Name: "ledger", CPUIters: 1, Upstreams: map[string]string{"account": ts1.URL},
		Routes: map[string]route{"/c2": {To: "account", Path: "/c2"}}}, nil)
	ts2 := httptest.NewServer(http.HandlerFunc(mid.handle))
	defer ts2.Close()
	resp, err := http.Get(ts2.URL + "/c2")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("chain failed: %v %v", err, resp)
	}
	if got := resp.Header.Get("X-Chain"); got != "ledger>account" {
		t.Errorf("X-Chain=%q", got)
	}
	resp2, _ := http.Get(ts2.URL + "/nope")
	if resp2.StatusCode != 404 {
		t.Errorf("unknown path want 404 got %d", resp2.StatusCode)
	}
	ts1.Close() // upstream down -> 502 surfaces to the caller
	resp3, _ := http.Get(ts2.URL + "/c2")
	if resp3.StatusCode != 502 {
		t.Errorf("want 502 got %d", resp3.StatusCode)
	}
}

func TestAppModeRejectsWithoutToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v, _ := newVerifierFromPEMFile(writePub(t, key), "", "")
	s := newServer(config{Name: "x", CPUIters: 1, JWTMode: "app", Routes: map[string]route{}}, v)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()
	if r, _ := http.Get(ts.URL + "/ping"); r.StatusCode != 401 {
		t.Errorf("want 401 got %d", r.StatusCode)
	}
	if r, _ := http.Get(ts.URL + "/healthz"); r.StatusCode != 200 {
		t.Errorf("healthz must stay open, got %d", r.StatusCode)
	}
}
