package main

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
)

func TestClientFollowsNoRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()
	response, err := httpClient(&tls.Config{}).Get(redirect.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || reached {
		t.Fatalf("redirect followed: %d %v", response.StatusCode, reached)
	}
}

func TestProbeSocket(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn, err := probeSocket("[::]:0", log)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	conn, err = probeSocket("127.0.0.1:0", log)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := probeSocket("no address", log); err == nil {
		t.Fatal("a bad address taken")
	}
}

// A new master makes its key; a database whose key is gone is refused.
func TestFirstKey(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Key: filepath.Join(dir, "data", "master.key"), DB: filepath.Join(dir, "data", "master.db")}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := firstKey(cfg, log); err != nil {
		t.Fatal(err)
	}
	key, err := sign.LoadSeed(cfg.Key)
	if err != nil {
		t.Fatalf("no key made: %v", err)
	}
	if info, _ := os.Stat(cfg.Key); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	// kept at the next start
	if err := firstKey(cfg, log); err != nil {
		t.Fatal(err)
	}
	if again, _ := sign.LoadSeed(cfg.Key); !again.Equal(key) {
		t.Fatal("the key was replaced")
	}
	// a database without its key
	os.Remove(cfg.Key)
	os.WriteFile(cfg.DB, []byte("db"), 0o600)
	if err := firstKey(cfg, log); err == nil || !strings.Contains(err.Error(), "restore the key") {
		t.Fatalf("a new key for an old database: %v", err)
	}
	// a key given as hex makes no file
	cfg.Key = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	if err := firstKey(cfg, log); err != nil {
		t.Fatal(err)
	}
}
