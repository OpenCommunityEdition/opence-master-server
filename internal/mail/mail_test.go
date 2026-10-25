package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// smtpServer answers one SMTP conversation: with STARTTLS offered or not,
// over implicit TLS or not; it returns its address and what it was sent.
func smtpServer(t *testing.T, config *tls.Config, implicit, starttls bool) (string, chan string) {
	t.Helper()
	var listener net.Listener
	var err error
	if implicit {
		listener, err = tls.Listen("tcp", "127.0.0.1:0", config)
	} else {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var log strings.Builder
		reader, writer := bufio.NewReader(conn), conn
		say := func(line string) { _, _ = writer.Write([]byte(line + "\r\n")) }
		say("220 test")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				got <- log.String()
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			log.WriteString(command + "\n")
			switch {
			case strings.HasPrefix(command, "EHLO"):
				if starttls {
					say("250-test")
					say("250 STARTTLS")
				} else {
					say("250 test")
				}
			case command == "STARTTLS":
				say("220 go ahead")
				secure := tls.Server(conn, config)
				if err := secure.Handshake(); err != nil {
					got <- log.String()
					return
				}
				conn, reader, writer = secure, bufio.NewReader(secure), secure
			case command == "DATA":
				say("354 go")
				for {
					data, err := reader.ReadString('\n')
					if err != nil || data == ".\r\n" {
						break
					}
				}
				say("250 ok")
			case command == "QUIT":
				say("221 bye")
				got <- log.String()
				return
			default:
				say("250 ok")
			}
		}
	}()
	return listener.Addr().String(), got
}

func certificate(t *testing.T) (*tls.Config, *tls.Config) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func TestMailNeedsTLS(t *testing.T) {
	server, client := certificate(t)
	// no STARTTLS offered: refused before anything is sent
	address, got := smtpServer(t, server, false, false)
	n := &Notifier{SMTPAddr: address, From: "master@example.org", TLSConfig: client}
	if err := n.send("op@example.org", []byte("Subject: x\r\n\r\nx\r\n")); err == nil ||
		!strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("sent without STARTTLS: %v", err)
	}
	if log := <-got; strings.Contains(log, "MAIL") {
		t.Fatalf("a mail sent in the clear: %s", log)
	}
	// STARTTLS offered: taken
	address, got = smtpServer(t, server, false, true)
	n.SMTPAddr = address
	if err := n.send("op@example.org", []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}
	if log := <-got; !strings.Contains(log, "STARTTLS\n") || !strings.Contains(log, "DATA") {
		t.Fatalf("conversation: %s", log)
	}
	// implicit TLS
	address, got = smtpServer(t, server, true, false)
	n.SMTPAddr, n.TLS = address, "tls"
	if err := n.send("op@example.org", []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}
	if log := <-got; !strings.Contains(log, "DATA") {
		t.Fatalf("conversation: %s", log)
	}
}
