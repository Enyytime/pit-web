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


	// Anything the website doesn't claim is the pit client API (push/pull):
	// /REPO/objects, /REPO/objects/HASH and /REPO/refs/BRANCH.
	mux.HandleFunc("/", h.API)

	return middleware.SecureHeaders(middleware.Authenticate(db)(mux))
}
