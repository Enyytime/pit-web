// Package routes maps URLs to handlers.
package routes

import (
	"net/http"

	"github.com/Enyytime/pit-web/handlers"
	"github.com/Enyytime/pit-web/middleware"
	"github.com/Enyytime/pit-web/models"
)

// New returns the complete HTTP handler: every route, wrapped in the security
// headers and authentication middleware.
func New(h *handlers.App, db *models.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.Home)

	mux.HandleFunc("/login", h.Login)
	mux.HandleFunc("POST /logout", h.Logout)
	mux.HandleFunc("/setup", h.Setup)
	mux.HandleFunc("/signup", h.Signup)

	mux.HandleFunc("GET /settings", h.Settings)
	mux.HandleFunc("POST /settings/password", h.ChangePassword)
	mux.HandleFunc("POST /settings/tokens", h.CreateToken)
	mux.HandleFunc("POST /settings/tokens/{id}/delete", h.DeleteToken)

	mux.HandleFunc("GET /admin", h.Admin)
	mux.HandleFunc("POST /admin/invites", h.CreateInvite)
	mux.HandleFunc("POST /admin/invites/{id}/delete", h.DeleteInvite)
	mux.HandleFunc("POST /admin/adopt", h.Adopt)

	mux.HandleFunc("POST /r/{repo}/visibility", h.SetVisibility)
	mux.HandleFunc("GET /r/{repo}", h.ListBranches)
	mux.HandleFunc("GET /r/{repo}/{branch}", h.CommitLog)
	mux.HandleFunc("GET /r/{repo}/commit/{hash}", h.ShowCommit)
	mux.HandleFunc("GET /r/{repo}/tree/{hash}", h.ShowTree)
	mux.HandleFunc("GET /r/{repo}/blob/{hash}", h.ShowBlob)
	mux.HandleFunc("GET /r/{repo}/raw/{hash}", h.RawBlob)

	// Anything the website doesn't claim is the pit client API (push/pull):
	// /REPO/objects, /REPO/objects/HASH and /REPO/refs/BRANCH.
	mux.HandleFunc("/", h.API)

	return middleware.SecureHeaders(middleware.Authenticate(db)(mux))
}
