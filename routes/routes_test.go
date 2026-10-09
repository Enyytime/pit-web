package routes_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Enyytime/pit-web/handlers"
	"github.com/Enyytime/pit-web/models"
	"github.com/Enyytime/pit-web/routes"
	"github.com/Enyytime/pit-web/utils"
)

func init() { utils.Iterations = 1000 }

// ---------- harness ----------

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t    *testing.T
	root string
	db   *models.Store
	ws   *handlers.App
	ts   *httptest.Server
	clk  *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, root: filepath.Join(dir, "repos"), clk: &clock{t: time.Now()}}
	os.MkdirAll(e.root, 0o755)
	db, err := models.Open(filepath.Join(dir, "db.json"))
	if err != nil {
		t.Fatal(err)
	}
	db.Now = e.clk.Now
	e.db = db
	ws, err := handlers.New(handlers.Config{Root: e.root, DB: db, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.ws = ws
	e.ts = httptest.NewServer(routes.New(ws, db))
	t.Cleanup(e.ts.Close)
	return e
}

// addUser creates a user directly in the store.
func (e *env) addUser(name, pw string, admin bool) models.User {
	e.t.Helper()
	h, _ := utils.HashPassword(pw)
	if e.db.UserCount() == 0 {
		u, err := e.db.CreateFirstAdmin(name, h)
		if err != nil {
			e.t.Fatal(err)
		}
		return u
	}
	code, ch := utils.NewInviteCode()
	_ = code
	e.db.CreateInvite(ch, "test", 1, e.clk.Now().Add(time.Hour))
	u, err := e.db.RedeemInvite(ch, name, h)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: e.t, base: e.ts.URL, hc: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (c *client) do(req *http.Request) resp {
	c.t.Helper()
	r, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, string(b), r.Header}
}

func (c *client) get(path string) resp {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+path, nil)
	return c.do(req)
}

func (c *client) basic(path, user, pass string) resp {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+path, nil)
	req.SetBasicAuth(user, pass)
	return c.do(req)
}

func (c *client) post(path string, form url.Values) resp {
	c.t.Helper()
	req, _ := http.NewRequest("POST", c.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

var csrfRe = regexp.MustCompile(`name=csrf value="([^"]+)"`)

// csrf loads path and returns the CSRF token embedded in its first form.
func (c *client) csrf(path string) string {
	c.t.Helper()
	r := c.get(path)
	m := csrfRe.FindStringSubmatch(r.body)
	if m == nil {
		c.t.Fatalf("no csrf token on %s (status %d)", path, r.code)
	}
	return m[1]
}

// postForm fetches a CSRF token from formPage and posts form to action with it.
func (c *client) postForm(formPage, action string, form url.Values) resp {
	c.t.Helper()
	form.Set("csrf", c.csrf(formPage))
	return c.post(action, form)
}

func (c *client) login(user, pw string) resp {
	c.t.Helper()
	return c.postForm("/login", "/login", url.Values{"username": {user}, "password": {pw}})
}

func (c *client) mustLogin(user, pw string) {
	c.t.Helper()
	if r := c.login(user, pw); r.code != http.StatusSeeOther {
		c.t.Fatalf("login %s: status %d: %s", user, r.code, r.body)
	}
}

func loc(r resp) string { return r.hdr.Get("Location") }

func has(t *testing.T, r resp, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(r.body, s) {
			t.Errorf("response (%d) missing %q", r.code, s)
		}
	}
}

// ---------- repo fixtures (pit's on-disk object format) ----------

func mkobj(t *testing.T, root, repo, typ string, body []byte) string {
	t.Helper()
	full := append([]byte(fmt.Sprintf("%s %d\x00", typ, len(body))), body...)
	sum := sha1.Sum(full)
	h := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, repo, "objects", h[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write(full)
	zw.Close()
	if err := os.WriteFile(filepath.Join(dir, h[2:]), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

type te struct{ mode, name, hash string }

func mktree(t *testing.T, root, repo string, es ...te) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range es {
		raw, _ := hex.DecodeString(e.hash)
		fmt.Fprintf(&b, "%s %s\x00", e.mode, e.name)
		b.Write(raw)
	}
	return mkobj(t, root, repo, "tree", b.Bytes())
}

func mkcommit(t *testing.T, root, repo, tree, parent, msg string) string {
	t.Helper()
	s := "tree " + tree + "\n"
	if parent != "" {
		s += "parent " + parent + "\n"
	}
	s += "author Kenny <k@example.com> 1791120640 +0000\ncommitter Kenny <k@example.com> 1791120640 +0000\n\n" + msg + "\n"
	return mkobj(t, root, repo, "commit", []byte(s))
}

type fixture struct{ c1, c2, b1, b2, bin, sub string }

// mkrepo builds a two-commit repo with a branch "main".
func (e *env) mkrepo(name string) fixture {
	t, root := e.t, e.root
	f := fixture{}
	f.b1 = mkobj(t, root, name, "blob", []byte("one\ntwo\nthree\n"))
	f.b2 = mkobj(t, root, name, "blob", []byte("one\nTWO\nthree\nfour\n"))
	f.bin = mkobj(t, root, name, "blob", []byte{0, 1, 2, 3})
	f.sub = mktree(t, root, name, te{"100644", "deep.txt", f.b1})
	t1 := mktree(t, root, name, te{"100644", "a.txt", f.b1}, te{"100644", "gone.bin", f.bin}, te{"40000", "sub", f.sub})
	f.c1 = mkcommit(t, root, name, t1, "", "first")
	t2 := mktree(t, root, name, te{"100644", "a.txt", f.b2}, te{"100644", "new.txt", f.b1}, te{"40000", "sub", f.sub})
	f.c2 = mkcommit(t, root, name, t2, f.c1, "second <b>commit</b>")
	os.MkdirAll(filepath.Join(root, name, "refs"), 0o755)
	os.WriteFile(filepath.Join(root, name, "refs", "main"), []byte(f.c2+"\n"), 0o644)
	return f
}

// ---------- tests ----------

func TestFirstRunSetup(t *testing.T) {
	e := newEnv(t)
	code := e.ws.SetupCode()
	if code == "" {
		t.Fatal("no setup code generated with zero users")
	}
	c := e.client()
	if r := c.get("/"); r.code != 303 || loc(r) != "/setup" {
		t.Fatalf("/ with no users: %d %s", r.code, loc(r))
	}
	good := func(over url.Values) url.Values {
		v := url.Values{"setup_code": {code}, "username": {"kenny"}, "password": {"a long password"}, "confirm": {"a long password"}}
		for k, x := range over {
			v[k] = x
		}
		return v
	}
	if r := c.postForm("/setup", "/setup", good(url.Values{"setup_code": {"WRONGCODE"}})); r.code != 403 {
		t.Fatalf("wrong code: %d", r.code)
	}
	if r := c.postForm("/setup", "/setup", good(url.Values{"password": {"short"}, "confirm": {"short"}})); r.code != 400 {
		t.Fatalf("weak password: %d", r.code)
	}
	if r := c.postForm("/setup", "/setup", good(url.Values{"confirm": {"different password"}})); r.code != 400 {
		t.Fatalf("mismatched confirm: %d", r.code)
	}
	if e.db.UserCount() != 0 {
		t.Fatal("user created by a rejected setup")
	}
	if r := c.post("/setup", good(nil)); r.code != 400 { // no CSRF token
		t.Fatalf("setup without CSRF: %d", r.code)
	}
	if r := c.postForm("/setup", "/setup", good(nil)); r.code != 303 || loc(r) != "/admin" {
		t.Fatalf("setup: %d %s %s", r.code, loc(r), r.body)
	}
	has(t, c.get("/admin"), "Invite someone")
	if u, _ := e.db.UserByName("kenny"); !u.IsAdmin {
		t.Fatal("first user is not admin")
	}
	// Setup is closed once an account exists.
	if r := e.client().get("/setup"); r.code != 303 || loc(r) != "/login" {
		t.Fatalf("/setup after setup: %d %s", r.code, loc(r))
	}
}

func TestLoginLogout(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	c := e.client()
	if r := c.login("kenny", "wrong password"); r.code != 401 {
		t.Fatalf("bad password: %d", r.code)
	}
	if r := c.login("nobody", "a long password"); r.code != 401 {
		t.Fatalf("unknown user: %d", r.code)
	}
	c.mustLogin("KENNY", "a long password") // usernames are case-insensitive
	if r := c.get("/settings"); r.code != 200 {
		t.Fatalf("settings after login: %d", r.code)
	}
	if r := c.post("/logout", url.Values{}); r.code != 403 {
		t.Fatalf("logout without CSRF: %d", r.code)
	}
	if r := c.postForm("/settings", "/logout", url.Values{}); r.code != 303 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := c.get("/settings"); r.code != 303 || !strings.HasPrefix(loc(r), "/login") {
		t.Fatalf("settings after logout: %d %s", r.code, loc(r))
	}
}

func TestLoginRedirectsAreSameSiteOnly(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	for next, want := range map[string]string{
		"/r/demo":          "/r/demo",
		"//evil.example":   "/",
		"https://evil.com": "/",
		"/\\evil.com":      "/",
		"":                 "/",
	} {
		c := e.client()
		form := url.Values{"username": {"kenny"}, "password": {"a long password"}, "next": {next}}
		if r := c.postForm("/login", "/login", form); loc(r) != want {
			t.Errorf("next=%q redirected to %q, want %q", next, loc(r), want)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	c := e.client()
	for i := 0; i < 8; i++ {
		if r := c.login("kenny", "wrong password"); r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	// Locked out: even the correct password is refused.
	if r := c.login("kenny", "a long password"); r.code != 429 {
		t.Fatalf("expected 429, got %d", r.code)
	}
	e.clk.Add(16 * time.Minute)
	if r := c.login("kenny", "a long password"); r.code != 303 {
		t.Fatalf("lockout did not expire: %d", r.code)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	c := e.client()
	c.mustLogin("kenny", "a long password")
	e.clk.Add(31 * 24 * time.Hour)
	if r := c.get("/settings"); r.code != 303 {
		t.Fatalf("expired session still valid: %d", r.code)
	}
}

func TestRepoAccessControl(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	e.mkrepo("demo")
	e.mkrepo("legacy") // on disk, owned by nobody
	e.db.AddRepo("demo", admin.ID, false)

	anon, kc, bc := e.client(), e.client(), e.client()
	kc.mustLogin("kenny", "a long password")
	bc.mustLogin("bob", "bobs long password")

	// Anonymous: private and unclaimed repos bounce to login (same as a missing repo).
	for _, p := range []string{"/r/demo", "/r/demo/main", "/r/legacy", "/r/missing"} {
		if r := anon.get(p); r.code != 303 || !strings.HasPrefix(loc(r), "/login?next=") {
			t.Errorf("anon %s: %d %s", p, r.code, loc(r))
		}
	}
	// Signed in without permission: 404, indistinguishable from missing.
	for _, p := range []string{"/r/demo", "/r/demo/main", "/r/legacy", "/r/missing"} {
		if r := bc.get(p); r.code != 404 {
			t.Errorf("bob %s: %d", p, r.code)
		}
	}
	if r := kc.get("/r/demo/main"); r.code != 200 {
		t.Fatalf("owner: %d", r.code)
	}
	if r := kc.get("/r/legacy"); r.code != 200 {
		t.Fatalf("admin on unclaimed repo: %d", r.code)
	}
	if r := bc.get("/"); strings.Contains(r.body, "demo") || strings.Contains(r.body, "legacy") {
		t.Fatal("home page leaks private repos")
	}
	if r := kc.get("/"); !strings.Contains(r.body, "demo") || !strings.Contains(r.body, "unclaimed") {
		t.Fatal("admin home page should list demo and unclaimed legacy")
	}

	// Visibility toggle needs CSRF and ownership.
	if r := kc.post("/r/demo/visibility", url.Values{"public": {"1"}}); r.code != 403 {
		t.Fatalf("visibility without CSRF: %d", r.code)
	}
	if r := bc.postForm("/settings", "/r/demo/visibility", url.Values{"public": {"1"}}); r.code != 404 {
		t.Fatalf("non-owner changed visibility: %d", r.code)
	}
	if r := kc.postForm("/r/demo", "/r/demo/visibility", url.Values{"public": {"1"}}); r.code != 303 {
		t.Fatalf("owner visibility: %d", r.code)
	}
	for _, p := range []string{"/r/demo", "/r/demo/main"} {
		if r := anon.get(p); r.code != 200 {
			t.Errorf("anon on public repo %s: %d", p, r.code)
		}
	}
	if r := anon.get("/"); !strings.Contains(r.body, "demo") || !strings.Contains(r.body, "public") {
		t.Fatal("public repo missing from anonymous home page")
	}
	if r := anon.get("/r/legacy"); r.code != 303 {
		t.Fatalf("unclaimed repo became visible: %d", r.code)
	}
	kc.postForm("/r/demo", "/r/demo/visibility", url.Values{"public": {"0"}})
	if r := anon.get("/r/demo"); r.code != 303 {
		t.Fatalf("repo still public after making private: %d", r.code)
	}

	// Adopting assigns ownership.
	if r := bc.get("/admin"); r.code != 404 {
		t.Fatalf("non-admin reached /admin: %d", r.code)
	}
	if r := kc.postForm("/admin", "/admin/adopt", url.Values{"repo": {"legacy"}, "owner": {"bob"}}); r.code != 200 {
		t.Fatalf("adopt: %d %s", r.code, r.body)
	}
	if rp, _ := e.db.RepoByName("legacy"); rp.OwnerID != bob.ID || rp.Public {
		t.Fatalf("adopt result wrong: %+v", rp)
	}
	if r := bc.get("/r/legacy"); r.code != 200 {
		t.Fatalf("new owner cannot see adopted repo: %d", r.code)
	}
	if r := kc.postForm("/admin", "/admin/adopt", url.Values{"repo": {"../etc"}}); r.code != 400 {
		t.Fatalf("adopt traversal: %d", r.code)
	}
}

var inviteRe = regexp.MustCompile(`/signup\?invite=([A-Za-z0-9_%-]+)`)

func TestInviteSignup(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	kc := e.client()
	kc.mustLogin("kenny", "a long password")

	mkInvite := func() string {
		r := kc.postForm("/admin", "/admin/invites", url.Values{"note": {"for bob"}, "days": {"7"}})
		m := inviteRe.FindStringSubmatch(r.body)
		if r.code != 200 || m == nil {
			t.Fatalf("create invite: %d %s", r.code, r.body)
		}
		return m[1]
	}
	signup := func(c *client, code, name, pw string) resp {
		return c.postForm("/signup?invite="+code, "/signup", url.Values{
			"invite": {code}, "username": {name}, "password": {pw}, "confirm": {pw}})
	}

	anon := e.client()
	if r := anon.get("/signup"); r.code != 200 || strings.Contains(r.body, "name=username") {
		t.Fatalf("signup page without invite should show no form (%d)", r.code)
	}
	code := mkInvite()
	if r := signup(e.client(), "bogus-code", "bob", "bobs long password"); r.code != 403 {
		t.Fatalf("bogus invite: %d", r.code)
	}
	bc := e.client()
	if r := signup(bc, code, "bob", "weak"); r.code != 400 {
		t.Fatalf("weak password on signup: %d", r.code)
	}
	if r := signup(bc, code, "bob", "bobs long password"); r.code != 303 {
		t.Fatalf("signup: %d %s", r.code, r.body)
	}
	if r := bc.get("/settings"); r.code != 200 {
		t.Fatalf("not logged in after signup: %d", r.code)
	}
	if u, _ := e.db.UserByName("bob"); u.IsAdmin {
		t.Fatal("invited user became admin")
	}
	// One use only.
	if r := signup(e.client(), code, "mallory", "mallorys long password"); r.code != 403 {
		t.Fatalf("invite reused: %d", r.code)
	}
	// Taken usernames (case-insensitively) do not consume the invite.
	code2 := mkInvite()
	if r := signup(e.client(), code2, "BOB", "another long password"); r.code != 409 {
		t.Fatalf("duplicate username: %d", r.code)
	}
	if r := signup(e.client(), code2, "carol", "carols long password"); r.code != 303 {
		t.Fatalf("invite wrongly burned by failed signup: %d", r.code)
	}
	// Expired invites are refused.
	code3 := mkInvite()
	e.clk.Add(8 * 24 * time.Hour)
	if r := signup(e.client(), code3, "dave", "daves long password"); r.code != 403 {
		t.Fatalf("expired invite: %d", r.code)
	}
	// Non-admins cannot mint invites.
	if r := bc.postForm("/settings", "/admin/invites", url.Values{"note": {"x"}}); r.code != 404 {
		t.Fatalf("non-admin created invite: %d", r.code)
	}
}

var tokenRe = regexp.MustCompile(`pit_[0-9a-f]{64}`)

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	e.mkrepo("pub")
	e.mkrepo("priv")
	e.db.AddRepo("pub", admin.ID, true)
	e.db.AddRepo("priv", admin.ID, false)

	bc := e.client()
	bc.mustLogin("bob", "bobs long password")
	r := bc.postForm("/settings", "/settings/tokens", url.Values{"name": {"laptop"}, "scope": {"read"}})
	tok := tokenRe.FindString(r.body)
	if r.code != 200 || tok == "" {
		t.Fatalf("create token: %d", r.code)
	}
	if strings.Contains(bc.get("/settings").body, tok) {
		t.Fatal("token shown again after creation")
	}
	if stored, _ := os.ReadFile(filepath.Join(filepath.Dir(e.root), "db.json")); strings.Contains(string(stored), tok) {
		t.Fatal("raw token stored on disk; only its hash should be")
	}

	api := e.client()
	if r := api.basic("/r/pub", "bob", tok); r.code != 200 {
		t.Fatalf("token on public repo: %d", r.code)
	}
	if r := api.basic("/r/priv", "bob", tok); r.code != 404 {
		t.Fatalf("token reached admin's private repo: %d", r.code)
	}
	if r := api.basic("/r/pub", "BOB", tok); r.code != 200 {
		t.Fatalf("username should be case-insensitive: %d", r.code)
	}
	if r := api.basic("/r/pub", "kenny", tok); r.code != 401 || r.hdr.Get("WWW-Authenticate") == "" {
		t.Fatalf("token with someone else's username: %d", r.code)
	}
	if r := api.basic("/r/pub", "bob", "pit_"+strings.Repeat("0", 64)); r.code != 401 {
		t.Fatalf("wrong token: %d", r.code)
	}
	if r := api.basic("/settings", "bob", tok); r.code != 303 {
		t.Fatalf("API token reached the account pages: %d", r.code)
	}
	// Tokens cannot be used as passwords for browser login.
	if r := e.client().login("bob", tok); r.code != 401 {
		t.Fatalf("token accepted as a password: %d", r.code)
	}

	// Another user cannot revoke it; the owner can.
	kc := e.client()
	kc.mustLogin("kenny", "a long password")
	toks := e.db.ListTokens(bob.ID)
	if len(toks) != 1 {
		t.Fatalf("tokens: %v", toks)
	}
	path := fmt.Sprintf("/settings/tokens/%d/delete", toks[0].ID)
	if r := kc.postForm("/settings", path, url.Values{}); r.code != 404 {
		t.Fatalf("revoked someone else's token: %d", r.code)
	}
	if r := bc.postForm("/settings", path, url.Values{}); r.code != 200 {
		t.Fatalf("revoke: %d", r.code)
	}
	if r := api.basic("/r/pub", "bob", tok); r.code != 401 {
		t.Fatalf("revoked token still works: %d", r.code)
	}
}

func TestCSRFProtection(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	c := e.client()
	c.mustLogin("kenny", "a long password")
	form := url.Values{"name": {"x"}, "scope": {"read"}}
	if r := c.post("/settings/tokens", form); r.code != 403 {
		t.Fatalf("no CSRF token: %d", r.code)
	}
	form.Set("csrf", "not-the-token")
	if r := c.post("/settings/tokens", form); r.code != 403 {
		t.Fatalf("wrong CSRF token: %d", r.code)
	}
	if len(e.db.ListTokens(1)) != 0 {
		t.Fatal("token created despite CSRF failure")
	}
	// Login CSRF: a form posted without the matching cookie is refused.
	form = url.Values{"username": {"kenny"}, "password": {"a long password"}, "csrf": {"attacker-chosen"}}
	if r := e.client().post("/login", form); r.code != 400 {
		t.Fatalf("login without pre-session cookie: %d", r.code)
	}
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "old long password", true)
	a, b := e.client(), e.client()
	a.mustLogin("kenny", "old long password")
	b.mustLogin("kenny", "old long password")

	change := func(cur, nw, conf string) resp {
		return a.postForm("/settings", "/settings/password", url.Values{"current": {cur}, "password": {nw}, "confirm": {conf}})
	}
	if r := change("wrong", "new long password", "new long password"); r.code != 403 {
		t.Fatalf("wrong current password: %d", r.code)
	}
	if r := change("old long password", "new long password", "different"); r.code != 400 {
		t.Fatalf("mismatch: %d", r.code)
	}
	if r := change("old long password", "short", "short"); r.code != 400 {
		t.Fatalf("weak: %d", r.code)
	}
	if r := change("old long password", "new long password", "new long password"); r.code != 200 {
		t.Fatalf("change: %d", r.code)
	}
	if r := a.get("/settings"); r.code != 200 {
		t.Fatal("current session was signed out by its own password change")
	}
	if r := b.get("/settings"); r.code != 303 {
		t.Fatalf("other device still signed in: %d", r.code)
	}
	if r := e.client().login("kenny", "old long password"); r.code != 401 {
		t.Fatalf("old password still works: %d", r.code)
	}
	if r := e.client().login("kenny", "new long password"); r.code != 303 {
		t.Fatalf("new password rejected: %d", r.code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	r := e.client().get("/login")
	for h, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "private, no-store",
	} {
		if r.hdr.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, r.hdr.Get(h), want)
		}
	}
	if csp := r.hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP = %q", csp)
	}
	ck := r.hdr.Values("Set-Cookie")
	if len(ck) == 0 || !strings.Contains(ck[0], "HttpOnly") || !strings.Contains(ck[0], "SameSite=Lax") {
		t.Errorf("pre-login cookie flags: %v", ck)
	}
}

func TestSecureCookieFlag(t *testing.T) {
	dir := t.TempDir()
	db, _ := models.Open(filepath.Join(dir, "db.json"))
	h, _ := utils.HashPassword("a long password")
	db.CreateFirstAdmin("kenny", h)
	ws, _ := handlers.New(handlers.Config{Root: dir, DB: db, SecureCookies: true})
	ts := httptest.NewServer(routes.New(ws, db))
	defer ts.Close()
	r, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	if ck := r.Header.Values("Set-Cookie"); len(ck) == 0 || !strings.Contains(ck[0], "Secure") {
		t.Errorf("Secure flag missing: %v", ck)
	}
}

func TestViewerPages(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("kenny", "a long password", true)
	f := e.mkrepo("demo")
	e.db.AddRepo("demo", admin.ID, false)
	c := e.client()
	c.mustLogin("kenny", "a long password")

	r := c.get("/r/demo/main")
	has(t, r, "/r/demo/commit/"+f.c2, "first")
	if strings.Contains(r.body, "<b>commit</b>") {
		t.Fatal("commit message not HTML-escaped in log")
	}

	r = c.get("/r/demo/commit/" + f.c2)
	has(t, r, "3 file(s) changed", "a.txt", "new.txt", "gone.bin", "binary file", "TWO", "&lt;b&gt;commit&lt;/b&gt;")
	if strings.Contains(r.body, "deep.txt") {
		t.Error("unchanged file listed in diff")
	}
	has(t, c.get("/r/demo/commit/"+f.c1), "3 file(s) changed") // root commit: all added

	r = c.get("/r/demo/tree/" + f.sub + "?p=sub")
	has(t, r, "deep.txt", "p=sub%2Fdeep.txt")
	has(t, c.get("/r/demo/blob/"+f.b2+"?p=a.txt"), "class=code", "/r/demo/raw/"+f.b2)

	r = c.get("/r/demo/raw/" + f.b2)
	if r.code != 200 || r.body != "one\nTWO\nthree\nfour\n" || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("raw: %d %q %s", r.code, r.body, r.hdr.Get("Content-Type"))
	}
	if r = c.get("/r/demo/raw/" + f.bin); r.hdr.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("binary raw type %q", r.hdr.Get("Content-Type"))
	}

	for _, p := range []string{"/r/demo/commit/zzz", "/r/..%2Fetc/main", "/r/demo/commit/" + strings.Repeat("0", 40), "/r/demo/tree/" + f.b1, "/r/demo/main/extra"} {
		if r := c.get(p); r.code != 404 {
			t.Errorf("%s -> %d, want 404", p, r.code)
		}
	}
}

func TestPagination(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("kenny", "a long password", true)
	tree := mktree(t, e.root, "big")
	parent := ""
	for i := 0; i < 55; i++ {
		parent = mkcommit(t, e.root, "big", tree, parent, fmt.Sprintf("commit-%03d", i))
	}
	os.MkdirAll(filepath.Join(e.root, "big", "refs"), 0o755)
	os.WriteFile(filepath.Join(e.root, "big", "refs", "main"), []byte(parent), 0o644)
	e.db.AddRepo("big", admin.ID, false)
	c := e.client()
	c.mustLogin("kenny", "a long password")

	p1 := c.get("/r/big/main")
	if !strings.Contains(p1.body, "older →") || strings.Count(p1.body, "/commit/") != 50 {
		t.Fatalf("page 1: %d commits", strings.Count(p1.body, "/commit/"))
	}
	p2 := c.get("/r/big/main?page=2")
	if strings.Contains(p2.body, "older →") || strings.Count(p2.body, "/commit/") != 5 || !strings.Contains(p2.body, "← newer") {
		t.Fatalf("page 2: %d commits", strings.Count(p2.body, "/commit/"))
	}
	if r := c.get("/r/big/main?page=9"); r.code != 404 {
		t.Fatalf("out-of-range page: %d", r.code)
	}
}
