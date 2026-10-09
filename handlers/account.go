package handlers

import (
	"errors"
	"github.com/Enyytime/pit-web/middleware"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Enyytime/pit-web/models"
	"github.com/Enyytime/pit-web/utils"
)

// ---------- login / logout ----------

func (s *App) Login(w http.ResponseWriter, r *http.Request) {
	a := middleware.Who(r)
	next := safeNext(r.URL.Query().Get("next"))
	if r.Method == http.MethodPost {
		next = safeNext(r.PostFormValue("next"))
	}
	if a.Sess != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	if s.cfg.DB.UserCount() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	fail := func(status int, msg string) {
		p := s.prePage(w, r, "Log in · pit")
		p.Err, p.Next = msg, next
		s.render(w, "login", status, p)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		fail(http.StatusOK, "")
	case http.MethodPost:
		if !parseForm(w, r) {
			return
		}
		if !s.checkPre(r) {
			fail(http.StatusBadRequest, "Your form expired. Please try again.")
			return
		}
		ip := s.clientIP(r)
		name := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
		pw := r.PostFormValue("password")
		if !s.loginIP.Allow(ip) || !s.loginUser.Allow(name) {
			fail(http.StatusTooManyRequests, "Too many failed attempts. Try again in 15 minutes.")
			return
		}
		u, ok := s.cfg.DB.UserByName(name)
		valid := false
		if ok && len(pw) <= utils.MaxPassword {
			valid = utils.CheckPassword(pw, u.PassHash)
		} else {
			utils.CheckAgainstDummy(pw)
		}
		if !valid {
			s.loginIP.Fail(ip)
			s.loginUser.Fail(name)
			fail(http.StatusUnauthorized, "Invalid username or password.")
			return
		}
		s.loginUser.Reset(name)
		if err := s.startSession(w, r, u); err != nil {
			http.Error(w, "could not start session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *App) Logout(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requirePost(w, r)
	if !ok {
		return
	}
	s.cfg.DB.DeleteSession(a.Sess.Hash)
	s.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------- first-run setup and invite signup ----------

type credsForm struct{ username, pw, confirm string }

func readCreds(r *http.Request) credsForm {
	return credsForm{
		username: strings.TrimSpace(r.PostFormValue("username")),
		pw:       r.PostFormValue("password"),
		confirm:  r.PostFormValue("confirm"),
	}
}

func (c credsForm) validate() string {
	if !models.ValidUsername(c.username) {
		return models.ErrBadName.Error()
	}
	if c.pw != c.confirm {
		return "Passwords do not match."
	}
	if err := utils.ValidPassword(c.pw); err != nil {
		return capitalize(err.Error()) + "."
	}
	return ""
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *App) Setup(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DB.UserCount() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	show := func(status int, msg, username string) {
		p := s.prePage(w, r, "Set up · pit")
		p.Err = msg
		p.Data = username
		s.render(w, "setup", status, p)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		show(http.StatusOK, "", "")
	case http.MethodPost:
		if !parseForm(w, r) {
			return
		}
		if !s.checkPre(r) {
			show(http.StatusBadRequest, "Your form expired. Please try again.", "")
			return
		}
		ip := s.clientIP(r)
		if !s.loginIP.Allow(ip) {
			show(http.StatusTooManyRequests, "Too many attempts. Try again in 15 minutes.", "")
			return
		}
		c := readCreds(r)
		if s.setupCode == "" || !utils.Equal(strings.TrimSpace(r.PostFormValue("setup_code")), s.setupCode) {
			s.loginIP.Fail(ip)
			show(http.StatusForbidden, "Wrong setup code. It is printed in the server log at startup.", c.username)
			return
		}
		if msg := c.validate(); msg != "" {
			show(http.StatusBadRequest, msg, c.username)
			return
		}
		hash, err := utils.HashPassword(c.pw)
		if err != nil {
			http.Error(w, "hashing failed", http.StatusInternalServerError)
			return
		}
		u, err := s.cfg.DB.CreateFirstAdmin(c.username, hash)
		if err != nil {
			if errors.Is(err, models.ErrNotEmpty) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			show(http.StatusBadRequest, err.Error(), c.username)
			return
		}
		s.setupCode = ""
		if err := s.startSession(w, r, u); err != nil {
			http.Error(w, "could not start session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *App) Signup(w http.ResponseWriter, r *http.Request) {
	if middleware.Who(r).Sess != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	code := r.URL.Query().Get("invite")
	if r.Method == http.MethodPost {
		code = r.PostFormValue("invite")
	}
	show := func(status int, msg, username string) {
		p := s.prePage(w, r, "Sign up · pit")
		p.Err = msg
		p.Data = map[string]string{"Invite": code, "Username": username}
		s.render(w, "signup", status, p)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if code == "" {
			show(http.StatusOK, "Sign-up is by invitation only. Ask the admin for an invite link.", "")
			return
		}
		show(http.StatusOK, "", "")
	case http.MethodPost:
		if !parseForm(w, r) {
			return
		}
		code = r.PostFormValue("invite")
		if !s.checkPre(r) {
			show(http.StatusBadRequest, "Your form expired. Please try again.", "")
			return
		}
		ip := s.clientIP(r)
		if !s.loginIP.Allow(ip) {
			show(http.StatusTooManyRequests, "Too many attempts. Try again in 15 minutes.", "")
			return
		}
		c := readCreds(r)
		if msg := c.validate(); msg != "" {
			show(http.StatusBadRequest, msg, c.username)
			return
		}
		hash, err := utils.HashPassword(c.pw)
		if err != nil {
			http.Error(w, "hashing failed", http.StatusInternalServerError)
			return
		}
		u, err := s.cfg.DB.RedeemInvite(utils.Hash(code), c.username, hash)
		switch {
		case errors.Is(err, models.ErrBadInvite):
			s.loginIP.Fail(ip)
			show(http.StatusForbidden, "This invite is invalid, expired or already used.", c.username)
			return
		case errors.Is(err, models.ErrExists):
			show(http.StatusConflict, "That username is taken.", c.username)
			return
		case err != nil:
			show(http.StatusBadRequest, err.Error(), c.username)
			return
		}
		if err := s.startSession(w, r, u); err != nil {
			http.Error(w, "could not start session", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- settings: password and API tokens ----------

type settingsData struct {
	Tokens   []models.Token
	NewToken string // shown once, right after creation
	BaseURL  string
	Scheme   string
	Host     string
	Username string
}

func (s *App) renderSettings(w http.ResponseWriter, r *http.Request, a middleware.Info, status int, msg, errMsg, newToken string) {
	p := s.newPage(r, "Settings · pit")
	p.Msg, p.Err = msg, errMsg
	p.Data = settingsData{
		Tokens: s.cfg.DB.ListTokens(a.User.ID), NewToken: newToken,
		BaseURL: s.baseURL(r), Scheme: scheme(r), Host: r.Host, Username: a.User.Username,
	}
	s.render(w, "settings", status, p)
}

func (s *App) Settings(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	s.renderSettings(w, r, a, http.StatusOK, "", "", "")
}

func (s *App) ChangePassword(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requirePost(w, r)
	if !ok {
		return
	}
	cur, pw, confirm := r.PostFormValue("current"), r.PostFormValue("password"), r.PostFormValue("confirm")
	switch {
	case !utils.CheckPassword(cur, a.User.PassHash):
		s.renderSettings(w, r, a, http.StatusForbidden, "", "Current password is incorrect.", "")
		return
	case pw != confirm:
		s.renderSettings(w, r, a, http.StatusBadRequest, "", "New passwords do not match.", "")
		return
	}
	if err := utils.ValidPassword(pw); err != nil {
		s.renderSettings(w, r, a, http.StatusBadRequest, "", capitalize(err.Error())+".", "")
		return
	}
	hash, err := utils.HashPassword(pw)
	if err != nil || s.cfg.DB.SetPassword(a.User.ID, hash) != nil {
		http.Error(w, "could not change password", http.StatusInternalServerError)
		return
	}
	// Sign out every other device.
	s.cfg.DB.DeleteUserSessions(a.User.ID, a.Sess.Hash)
	s.renderSettings(w, r, a, http.StatusOK, "Password changed. Other devices were signed out.", "", "")
}

func (s *App) CreateToken(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requirePost(w, r)
	if !ok {
		return
	}
	tok, hash := utils.NewAPIToken()
	_, err := s.cfg.DB.CreateToken(a.User.ID, r.PostFormValue("name"), hash, r.PostFormValue("scope") == "write")
	if err != nil {
		msg := err.Error()
		if errors.Is(err, models.ErrLimit) {
			msg = "Token limit reached. Revoke one first."
		}
		s.renderSettings(w, r, a, http.StatusBadRequest, "", capitalize(msg)+".", "")
		return
	}
	s.renderSettings(w, r, a, http.StatusOK, "Token created. Copy it now — it will not be shown again.", "", tok)
}

func (s *App) DeleteToken(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requirePost(w, r)
	if !ok {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.cfg.DB.DeleteToken(a.User.ID, id); err != nil {
		notFound(w)
		return
	}
	s.renderSettings(w, r, a, http.StatusOK, "Token revoked.", "", "")
}

// ---------- admin ----------

type adminData struct {
	Users     []models.User
	Invites   []models.Invite
	Unclaimed []string
	NewLink   string // shown once, right after creating an invite
}

func (s *App) requireAdmin(w http.ResponseWriter, r *http.Request, post bool) (middleware.Info, bool) {
	var a middleware.Info
	var ok bool
	if post {
		a, ok = s.requirePost(w, r)
	} else {
		a, ok = s.requireSession(w, r)
	}
	if !ok {
		return a, false
	}
	if !a.User.IsAdmin {
		notFound(w)
		return a, false
	}
	return a, true
}

func (s *App) renderAdmin(w http.ResponseWriter, r *http.Request, status int, msg, errMsg, newLink string) {
	p := s.newPage(r, "Admin · pit")
	p.Msg, p.Err = msg, errMsg
	d := adminData{Users: s.cfg.DB.ListUsers(), Invites: s.cfg.DB.ListInvites(), NewLink: newLink}
	if ents, err := os.ReadDir(s.cfg.Root); err == nil {
		for _, e := range ents {
			if e.IsDir() && utils.ValidName(e.Name()) {
				if _, claimed := s.cfg.DB.RepoByName(e.Name()); !claimed {
					d.Unclaimed = append(d.Unclaimed, e.Name())
				}
			}
		}
	}
	p.Data = d
	s.render(w, "admin", status, p)
}

func (s *App) Admin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r, false); !ok {
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "", "", "")
}

func (s *App) CreateInvite(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAdmin(w, r, true)
	if !ok {
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	if days < 1 || days > 30 {
		days = 7
	}
	code, hash := utils.NewInviteCode()
	_, err := s.cfg.DB.CreateInvite(hash, r.PostFormValue("note"), a.User.ID, s.cfg.Now().Add(time.Duration(days)*24*time.Hour))
	if err != nil {
		s.renderAdmin(w, r, http.StatusBadRequest, "", "Could not create invite: "+err.Error(), "")
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "Invite created. Copy the link now — it will not be shown again.", "",
		s.baseURL(r)+"/signup?invite="+url.QueryEscape(code))
}

func (s *App) DeleteInvite(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r, true); !ok {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.cfg.DB.DeleteInvite(id); err != nil {
		notFound(w)
		return
	}
	s.renderAdmin(w, r, http.StatusOK, "Invite deleted.", "", "")
}

// Adopt assigns an on-disk repository that nobody owns yet to a user.
func (s *App) Adopt(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAdmin(w, r, true)
	if !ok {
		return
	}
	repo := r.PostFormValue("repo")
	owner, found := s.cfg.DB.UserByName(r.PostFormValue("owner"))
	if !found {
		owner = *a.User
	}
	if !utils.ValidName(repo) || !dirExists(s.cfg.Root+"/"+repo) {
		s.renderAdmin(w, r, http.StatusBadRequest, "", "No such repository on disk.", "")
		return
	}
	if err := s.cfg.DB.AddRepo(repo, owner.ID, r.PostFormValue("public") == "1"); err != nil {
		s.renderAdmin(w, r, http.StatusBadRequest, "", "Repository is already claimed.", "")
		return
	}
	s.renderAdmin(w, r, http.StatusOK, repo+" now belongs to "+owner.Username+" (private).", "", "")
}
