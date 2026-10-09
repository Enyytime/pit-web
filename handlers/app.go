// Package handlers serves the pit viewer, the account system and the push/pull API.
package handlers

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Enyytime/pit-web/frontend"
	"github.com/Enyytime/pit-web/middleware"
	"github.com/Enyytime/pit-web/models"
	"github.com/Enyytime/pit-web/utils"
)

const (
	sessionCookie = "pit_session"
	preCookie     = "pit_pre"
	sessionTTL    = 30 * 24 * time.Hour
	maxForm       = 64 << 10
)

// Config configures an App.
type Config struct {
	Root          string        // directory holding <repo>/objects and <repo>/refs
	DB            *models.Store // accounts
	SecureCookies bool          // set the Secure flag on cookies (true behind HTTPS)
	Now           func() time.Time
}

type App struct {
	cfg  Config
	obj  utils.ObjectStore
	tpls map[string]*template.Template

	loginIP   *utils.RateLimiter // failed logins per client IP
	loginUser *utils.RateLimiter // failed logins per username
	setupCode string             // required by /setup while there are no users
	pushMu    sync.Mutex         // serialises branch updates so fast-forward checks cannot race
}

// New builds the App. While the database has no users, it generates a
// one-time setup code that /setup requires; read it with SetupCode.
func New(cfg Config) (*App, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &App{
		cfg:       cfg,
		obj:       utils.ObjectStore{Root: cfg.Root},
		tpls:      map[string]*template.Template{},
		loginIP:   utils.NewRateLimiter(20, 15*time.Minute),
		loginUser: utils.NewRateLimiter(8, 15*time.Minute),
	}
	s.loginIP.Now, s.loginUser.Now = cfg.Now, cfg.Now
	fm := template.FuncMap{
		"date": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.UTC().Format("2006-01-02 15:04")
		},
	}
	for _, name := range []string{"viewer", "login", "setup", "signup", "settings", "admin"} {
		t, err := template.New("base.html").Funcs(fm).ParseFS(frontend.FS, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		s.tpls[name] = t
	}
	if cfg.DB.UserCount() == 0 {
		s.setupCode = utils.RandomString(12)
	}
	return s, nil
}

// SetupCode returns the first-run setup code, or "" if users already exist.
func (s *App) SetupCode() string { return s.setupCode }

// peerIsProxy is true when the direct peer is on this machine, i.e. Caddy.
func peerIsProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// clientIP returns the caller's address, trusting X-Forwarded-For only when
// the request came from a local reverse proxy. The proxy appends the real
// client address, so the last entry is the one to use.
func (s *App) clientIP(r *http.Request) string {
	if peerIsProxy(r) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func scheme(r *http.Request) string {
	if r.TLS != nil || (peerIsProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https") {
		return "https"
	}
	return "http"
}

func (s *App) baseURL(r *http.Request) string { return scheme(r) + "://" + r.Host }

// ---------- rendering ----------

type page struct {
	Title string
	User  *models.User
	CSRF  string
	Err   string
	Msg   string
	Next  string
	Body  template.HTML // viewer pages: pre-escaped HTML
	Data  any
}

func (s *App) newPage(r *http.Request, title string) *page {
	a := middleware.Who(r)
	p := &page{Title: title, User: a.User}
	if a.Sess != nil {
		p.CSRF = a.Sess.CSRF
	}
	return p
}

func (s *App) render(w http.ResponseWriter, name string, status int, p *page) {
	var buf strings.Builder
	if err := s.tpls[name].ExecuteTemplate(&buf, "base.html", p); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, buf.String())
}

// viewer renders pre-escaped HTML inside the page layout.
func (s *App) viewer(w http.ResponseWriter, r *http.Request, title, body string) {
	p := s.newPage(r, title)
	p.Body = template.HTML(body) // callers build body with esc() on every dynamic value
	s.render(w, "viewer", http.StatusOK, p)
}

func notFound(w http.ResponseWriter) { http.Error(w, "not found", http.StatusNotFound) }

// ---------- CSRF and cookies ----------

func (s *App) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode,
	})
}

// prePage prepares a page for a pre-login form (login, setup, signup) and sets
// a double-submit CSRF cookie that checkPre verifies on POST.
func (s *App) prePage(w http.ResponseWriter, r *http.Request, title string) *page {
	p := s.newPage(r, title)
	tok := utils.RandomString(32)
	s.setCookie(w, preCookie, tok, 3600)
	p.CSRF = tok
	return p
}

func (s *App) checkPre(r *http.Request) bool {
	c, err := r.Cookie(preCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return utils.Equal(c.Value, r.PostFormValue("csrf"))
}

// parseForm limits the body size and parses the form.
func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

// requireSession returns the logged-in user for pages that need a browser
// session (API tokens are not accepted here). It redirects to /login otherwise.
func (s *App) requireSession(w http.ResponseWriter, r *http.Request) (middleware.Info, bool) {
	a := middleware.Who(r)
	if a.Sess == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return a, false
	}
	return a, true
}

// requirePost is requireSession plus form parsing and CSRF verification.
func (s *App) requirePost(w http.ResponseWriter, r *http.Request) (middleware.Info, bool) {
	a := middleware.Who(r)
	if a.Sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return a, false
	}
	if !parseForm(w, r) {
		return a, false
	}
	if !utils.Equal(a.Sess.CSRF, r.PostFormValue("csrf")) {
		http.Error(w, "invalid CSRF token — go back, reload the page and try again", http.StatusForbidden)
		return a, false
	}
	return a, true
}

// safeNext only allows same-site relative redirects.
func safeNext(n string) string {
	if n == "" || n[0] != '/' || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") || strings.ContainsAny(n, "\r\n") {
		return "/"
	}
	return n
}

// startSession creates a fresh session (replacing any old one) and sets the cookie.
func (s *App) startSession(w http.ResponseWriter, r *http.Request, u models.User) error {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.cfg.DB.DeleteSession(utils.Hash(c.Value))
	}
	id, hash := utils.NewSessionID()
	err := s.cfg.DB.CreateSession(models.Session{
		Hash: hash, UserID: u.ID, CSRF: utils.RandomString(32), Expires: s.cfg.Now().Add(sessionTTL),
	})
	if err != nil {
		return err
	}
	s.setCookie(w, sessionCookie, id, int(sessionTTL.Seconds()))
	return nil
}

// ---------- repo access ----------

func (s *App) canView(u *models.User, repo string) bool {
	rp, ok := s.cfg.DB.RepoByName(repo)
	if ok && rp.Public {
		return true
	}
	if u == nil {
		return false
	}
	if u.IsAdmin {
		return true
	}
	return ok && rp.OwnerID == u.ID
}

func (s *App) canManage(u *models.User, repo string) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin {
		return true
	}
	rp, ok := s.cfg.DB.RepoByName(repo)
	return ok && rp.OwnerID == u.ID
}

// repoAccess validates the {repo} path value and checks the caller may read it.
// Anonymous callers are sent to the login page and signed-in callers get a 404,
// so a private repo and a missing repo look the same.
func (s *App) repoAccess(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("repo")
	if !utils.ValidName(name) {
		notFound(w)
		return "", false
	}
	a := middleware.Who(r)
	if s.canView(a.User, name) {
		return name, true
	}
	if a.User == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return "", false
	}
	notFound(w)
	return "", false
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
