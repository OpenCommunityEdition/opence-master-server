package main

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
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
