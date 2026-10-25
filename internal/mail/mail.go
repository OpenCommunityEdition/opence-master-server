// Package mail sends the master's notices: mails to operators (through SMTP,
// or written to the log when no SMTP server is set) and a webhook message
// to the admins.
package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Notifier sends mails and webhook messages, each on its own goroutine.
type Notifier struct {
	SMTPAddr, User, Password, From string
	// "auto" (implicit TLS on port 465, else STARTTLS), "starttls", "tls"
	// (implicit), or "none" (an SMTP server on loopback only); STARTTLS is
	// required, never skipped
	TLS string
	// the certificate authorities for the SMTP server (nil: the system's)
	TLSConfig *tls.Config
	Webhook   string
	Client    *http.Client
	Log       *slog.Logger
	// tests wait for sends with it
	Sync bool
}

// MailTimeout bounds a mail's whole SMTP conversation.
const MailTimeout = 30 * time.Second

// send delivers one message over SMTP, with TLS as n.TLS says.
func (n *Notifier) send(to string, message []byte) error {
	host, port, err := net.SplitHostPort(n.SMTPAddr)
	if err != nil {
		return fmt.Errorf("MASTER_SMTP_ADDR is host:port: %w", err)
	}
	mode := n.TLS
	if mode == "" || mode == "auto" {
		mode = "starttls"
		if port == "465" {
			mode = "tls"
		}
	}
	config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if n.TLSConfig != nil {
		config = n.TLSConfig.Clone()
		config.ServerName = host
	}
	dialer := &net.Dialer{Timeout: MailTimeout}
	var conn net.Conn
	if mode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", n.SMTPAddr, config)
	} else {
		conn, err = dialer.Dial("tcp", n.SMTPAddr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(MailTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server does not offer STARTTLS (MASTER_SMTP_TLS)")
		}
		if err := client.StartTLS(config); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if n.User != "" {
		if err := client.Auth(smtp.PlainAuth("", n.User, n.Password, host)); err != nil {
			return err
		}
	}
	if err := client.Mail(n.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(message); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (n *Notifier) run(f func()) {
	if n.Sync {
		f()
		return
	}
	go f()
}

func clean(text string) string {
	return strings.NewReplacer("\r", "", "\n", " ").Replace(text)
}

// Mail sends a mail; with no SMTP server it is written to the log whole, so
// the master's operator can pass it on.
func (n *Notifier) Mail(to, subject, body string) {
	to, subject = clean(to), clean(subject)
	if n.SMTPAddr == "" {
		n.Log.Info("mail (no MASTER_SMTP_ADDR: logged, not sent)", "to", to, "subject", subject, "body", body)
		return
	}
	n.run(func() {
		message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", n.From, to, subject,
			time.Now().UTC().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))
		if err := n.send(to, []byte(message)); err != nil {
			n.Log.Warn("mail: not sent", "subject", subject, "err", err)
		}
	})
}

// Notify posts a message to the admins' webhook (Discord's {"content"}).
func (n *Notifier) Notify(text string) {
	if n.Webhook == "" {
		n.Log.Info("notice", "text", text)
		return
	}
	n.run(func() {
		// (no mentions: an applicant's name could hold @everyone)
		body, _ := json.Marshal(map[string]any{"content": text, "allowed_mentions": map[string]any{"parse": []string{}}})
		request, err := http.NewRequest(http.MethodPost, n.Webhook, bytes.NewReader(body))
		if err != nil {
			n.Log.Warn("webhook: bad URL", "err", err)
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := n.Client.Do(request)
		if err != nil {
			n.Log.Warn("webhook: not sent", "err", err)
			return
		}
		response.Body.Close()
		if response.StatusCode >= 300 {
			n.Log.Warn("webhook: refused", "status", response.StatusCode)
		}
	})
}
