// Package frontend holds the HTML templates, embedded in the binary.
package frontend

import "embed"

//go:embed templates/*.html
var FS embed.FS
