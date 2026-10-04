// Package config reads the settings pit-web takes from environment variables.
package config

import (
	"os"
	"path/filepath"
)

// Config is the server's configuration.
type Config struct {
	Root          string // PIT_DATA: directory holding <repo>/objects and <repo>/refs
	DBPath        string // PIT_DB: accounts file
	Addr          string // PIT_ADDR: listen address
	SecureCookies bool   // false only when PIT_INSECURE_COOKIES=1
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Load reads the environment, falling back to defaults under the home directory.
func Load() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Root:          envOr("PIT_DATA", filepath.Join(home, "pit-data")),
		DBPath:        envOr("PIT_DB", filepath.Join(home, "pit-web.json")),
		Addr:          envOr("PIT_ADDR", ":8081"),
		SecureCookies: os.Getenv("PIT_INSECURE_COOKIES") != "1",
	}
}
