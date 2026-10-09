// Package middleware wraps handlers with security headers and identifies who
// is calling (session cookie or API token).
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/Enyytime/pit-web/models"
	"github.com/Enyytime/pit-web/utils"
)

// Info describes who is making a request.
type Info struct {
	User  *models.User
	Sess  *models.Session // set for cookie sessions
	Token *models.Token   // set for Basic-auth API tokens
}

type ctxKey struct{}

// Who returns the caller identified by Authenticate (zero Info if anonymous).
func Who(r *http.Request) Info {
	a, _ := r.Context().Value(ctxKey{}).(Info)
	return a
}

// SecureHeaders adds the response headers every page gets.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "private, no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Authenticate identifies the caller from a session cookie or Basic-auth API
// token. An invalid Basic-auth header is rejected outright; no credentials
// means an anonymous caller, and handlers decide what that may do.
func Authenticate(db *models.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var a Info
			if name, secret, ok := r.BasicAuth(); ok {
				t, u, found := db.TokenByHash(utils.Hash(secret))
				if !found || !strings.EqualFold(u.Username, name) {
					w.Header().Set("WWW-Authenticate", `Basic realm="pit", charset="UTF-8"`)
					http.Error(w, "invalid credentials", http.StatusUnauthorized)
					return
				}
				db.TouchToken(t.ID)
				a.User, a.Token = &u, &t
			} else if c, err := r.Cookie("pit_session"); err == nil && c.Value != "" {
				if sess, u, ok := db.SessionByHash(utils.Hash(c.Value)); ok {
					a.User, a.Sess = &u, &sess
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
		})
	}
}
