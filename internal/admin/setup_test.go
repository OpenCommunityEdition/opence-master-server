package admin_test

import (
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/OpenCommunityEdition/opence-master-server/internal/admin"
	"github.com/OpenCommunityEdition/opence-master-server/internal/config"
	"github.com/OpenCommunityEdition/opence-master-server/internal/core"
	"github.com/OpenCommunityEdition/opence-master-server/internal/httpx"
	"github.com/OpenCommunityEdition/opence-master-server/internal/mail"
	"github.com/OpenCommunityEdition/opence-master-server/internal/sign"
	"github.com/OpenCommunityEdition/opence-master-server/internal/store"
	"github.com/OpenCommunityEdition/opence-master-server/internal/web"
)

// newMaster serves a master's pages with the options' defaults (no name,
// contact nor admin token) changed by change.
func newMaster(t *testing.T, change func(*config.Config)) (*core.Master, *admin.Admin, *httptest.Server) {
	t.Helper()
	values := config.Flags(flag.NewFlagSet("test", flag.ContinueOnError))
	for _, o := range config.Options {
		*values[o.Env] = o.Default
	}
	cfg, err := config.Load(values)
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(cfg)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := sign.NewSeed()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := core.New(st, key, cfg, &mail.Notifier{Log: log, Client: http.DefaultClient, Sync: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := admin.New(m, &httpx.Clients{})
	if err != nil {
		t.Fatal(err)
	}
	public, err := web.New(m, &httpx.Clients{})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.Routes(mux)
	public.Routes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
		st.Close()
	})
	return m, pages, server
}

type cookieJar struct{ cookies []*http.Cookie }

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.cookies = append(j.cookies, cookies...)
}
func (j *cookieJar) Cookies(*url.URL) []*http.Cookie { return j.cookies }

func get(t *testing.T, c *http.Client, link string) (int, string) {
	t.Helper()
	return read(t)(c.Get(link))
}

func post(t *testing.T, c *http.Client, link string, form url.Values) (int, string) {
	t.Helper()
	return read(t)(c.PostForm(link, form))
}

func read(t *testing.T) func(*http.Response, error) (int, string) {
	return func(response *http.Response, err error) (int, string) {
		return body(t, response, err)
	}
}

func body(t *testing.T, response *http.Response, err error) (int, string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

// The first launch: no name, no admin token; the setup link names the
// master and shows the admin token once, which then logs in.
func TestFirstLaunchSetup(t *testing.T) {
	m, pages, server := newMaster(t, nil)
	code := pages.SetupCode()
	if code == "" || m.Named() || m.Name() != core.UnnamedMaster {
		t.Fatalf("set up already: %q %q", code, m.Name())
	}
	browser := &http.Client{Jar: &cookieJar{}}
	// every admin page leads to the setup, which asks for its link
	if status, page := get(t, browser, server.URL+"/admin/applications"); status != 200 ||
		!strings.Contains(page, "not set up yet") || strings.Contains(page, `name="code"`) {
		t.Fatalf("%d\n%s", status, page)
	}
	if status, page := get(t, browser, server.URL+"/admin/setup?code=0123"); status != 200 ||
		strings.Contains(page, `name="code"`) {
		t.Fatalf("a wrong code's form: %d\n%s", status, page)
	}
	if _, page := get(t, browser, server.URL+"/admin/setup?code="+code); !strings.Contains(page, `name="code"`) {
		t.Fatalf("no form:\n%s", page)
	}
	if status, _ := post(t, browser, server.URL+"/admin/setup",
		url.Values{"code": {"wrong"}, "name": {"My master"}}); status != 403 || m.Named() {
		t.Fatalf("a wrong code taken: %d", status)
	}
	if status, page := post(t, browser, server.URL+"/admin/setup",
		url.Values{"code": {code}, "name": {""}}); status != 400 || !strings.Contains(page, "Name: ") {
		t.Fatalf("no name taken: %d\n%s", status, page)
	}
	status, page := post(t, browser, server.URL+"/admin/setup", url.Values{"code": {code},
		"name": {"Paul's master"}, "contact": {""}})
	token := regexp.MustCompile(`<code class="token">([0-9a-f]{64})</code>`).FindStringSubmatch(page)
	if status != 200 || token == nil || m.Name() != "Paul's master" || m.Contact() != "" || pages.SetupCode() != "" {
		t.Fatalf("%d %q\n%s", status, m.Name(), page)
	}
	// logged in by the setup
	if status, page := get(t, browser, server.URL+"/admin/applications"); status != 200 ||
		!strings.Contains(page, "Log out") {
		t.Fatalf("not logged in: %d\n%s", status, page)
	}
	// the link is good once
	if _, page := post(t, http.DefaultClient, server.URL+"/admin/setup", url.Values{"code": {code},
		"name": {"Taken over"}}); m.Name() != "Paul's master" || strings.Contains(page, `class="token"`) {
		t.Fatalf("set up twice: %q", m.Name())
	}
	// the token logs in; the settings change the contact
	request, _ := http.NewRequest("POST", server.URL+"/admin/settings",
		strings.NewReader(url.Values{"name": {"Paul's master"}, "contact": {"ops@example.org"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer "+token[1])
	if status, _ := read(t)(http.DefaultClient.Do(request)); status != 200 || m.Contact() != "ops@example.org" {
		t.Fatalf("settings: %d %q", status, m.Contact())
	}
	if _, page := get(t, http.DefaultClient, server.URL+"/"); !strings.Contains(page, "Paul&#39;s master") ||
		!strings.Contains(page, "Contact: ops@example.org") {
		t.Fatalf("the public page:\n%s", page)
	}
	// kept across a restart: a new Admin has no setup link
	again, err := admin.New(m, &httpx.Clients{})
	if err != nil || again.SetupCode() != "" {
		t.Fatalf("a setup link after the setup: %v", err)
	}
}

// With MASTER_ADMIN_TOKEN but no name, there is no setup link: the admin
// logs in and is sent to the settings to name the master.
func TestEnvironmentTokenWithoutName(t *testing.T) {
	const token = "admin-token-for-the-setup-tests-0123456789"
	m, pages, server := newMaster(t, func(cfg *config.Config) { cfg.AdminToken = token })
	if pages.SetupCode() != "" {
		t.Fatal("a setup link with MASTER_ADMIN_TOKEN")
	}
	browser := &http.Client{Jar: &cookieJar{}}
	post(t, browser, server.URL+"/admin/login", url.Values{"token": {token}})
	status, page := get(t, browser, server.URL+"/admin/applications")
	if status != 200 || !strings.Contains(page, "Name the master first") || m.Named() {
		t.Fatalf("%d\n%s", status, page)
	}
}
