// meshsvc: one configurable service used for every node of the synthetic
// topology. Using a single binary removes language/runtime variance from the
// overhead measurements (the polyglot/real-app case is covered by the
// tenge-tracker case study).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type route struct {
	To   string `json:"to"`
	Path string `json:"path"`
}

type config struct {
	Name         string
	Port         string
	Routes       map[string]route
	Upstreams    map[string]string
	PayloadBytes int
	CPUIters     int
	JWTMode      string
}

type server struct {
	cfg      config
	ver      *verifier
	client   *http.Client
	leafBody []byte
}

var sink uint32

func burn(n int) {
	var b [32]byte
	for i := 0; i < n; i++ {
		b = sha256.Sum256(b[:])
	}
	atomic.AddUint32(&sink, uint32(b[0]))
}

func (s *server) upstreamBase(name string) string {
	if u, ok := s.cfg.Upstreams[name]; ok {
		return strings.TrimRight(u, "/")
	}
	return "http://" + name + ":8080"
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	if s.cfg.JWTMode == "app" {
		if err := s.ver.checkHeader(r.Header.Get("Authorization"), time.Now()); err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}
	burn(s.cfg.CPUIters)
	rt, ok := s.cfg.Routes[r.URL.Path]
	if !ok {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Chain", s.cfg.Name)
		_, _ = w.Write([]byte("pong"))
		return
	}
	if rt.To == "" { // leaf of a chain
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Chain", s.cfg.Name)
		_, _ = w.Write(s.leafBody)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.upstreamBase(rt.To)+rt.Path, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if a := r.Header.Get("Authorization"); a != "" {
		req.Header.Set("Authorization", a) // token propagation
	}
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("X-Chain", s.cfg.Name+">"+resp.Header.Get("X-Chain"))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode) // propagate 401/403/5xx from deeper hops
	_, _ = io.Copy(w, resp.Body)
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func loadConfig() (config, error) {
	c := config{
		Name:         os.Getenv("SERVICE_NAME"),
		Port:         os.Getenv("PORT"),
		Routes:       map[string]route{},
		Upstreams:    map[string]string{},
		PayloadBytes: envInt("PAYLOAD_BYTES", 2048),
		CPUIters:     envInt("CPU_WORK_ITERS", 1000),
		JWTMode:      os.Getenv("JWT_MODE"),
	}
	if c.Name == "" {
		return c, errors.New("SERVICE_NAME is required")
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if v := os.Getenv("ROUTES"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Routes); err != nil {
			return c, err
		}
	}
	if v := os.Getenv("UPSTREAMS"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Upstreams); err != nil {
			return c, err
		}
	}
	return c, nil
}

func newServer(c config, ver *verifier) *server {
	tr := &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	pad := c.PayloadBytes - 32 - len(c.Name)
	if pad < 0 {
		pad = 0
	}
	body, _ := json.Marshal(map[string]string{"svc": c.Name, "pad": strings.Repeat("x", pad)})
	return &server{cfg: c, ver: ver, client: &http.Client{Transport: tr, Timeout: 10 * time.Second}, leafBody: body}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	var ver *verifier
	if cfg.JWTMode == "app" {
		ver, err = newVerifierFromPEMFile(os.Getenv("JWT_PUBKEY_FILE"), os.Getenv("JWT_ISS"), os.Getenv("JWT_AUD"))
		if err != nil {
			log.Fatalf("jwt verifier: %v", err)
		}
	}
	s := newServer(cfg, ver)
	srv := &http.Server{Addr: ":" + cfg.Port, Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	log.Printf("%s listening on :%s jwt=%q routes=%d", cfg.Name, cfg.Port, cfg.JWTMode, len(cfg.Routes))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
