// pit-web: a web viewer and account system for pit repositories.
//
//	pit-web                         run the server (same as "serve")
//	pit-web adopt USER REPO...      give on-disk repos to USER (private); "--all" adopts every unclaimed repo
//	pit-web reset-password USER     set a random temporary password and sign USER out everywhere
//	pit-web users                   list accounts
//
// Environment: PIT_DATA (repos dir), PIT_DB (accounts file), PIT_ADDR (listen
// address), PIT_INSECURE_COOKIES=1 (drop the Secure cookie flag; only for
// plain-HTTP testing on a non-localhost address).
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"pitweb/internal/auth"
	"pitweb/internal/objects"
	"pitweb/internal/store"
	"pitweb/internal/web"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	home, _ := os.UserHomeDir()
	root := envOr("PIT_DATA", filepath.Join(home, "pit-data"))
	db, err := store.Open(envOr("PIT_DB", filepath.Join(home, "pit-web.json")))
	if err != nil {
		log.Fatalf("cannot open accounts file: %v", err)
	}

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve(root, db)
	case "adopt":
		adopt(root, db, os.Args[2:])
	case "reset-password":
		resetPassword(db, os.Args[2:])
	case "users":
		for _, u := range db.ListUsers() {
			role := "user"
			if u.IsAdmin {
				role = "admin"
			}
			fmt.Printf("%-24s %s\n", u.Username, role)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\nusage: pit-web [serve | adopt USER REPO... | reset-password USER | users]\n", cmd)
		os.Exit(2)
	}
}

func serve(root string, db *store.Store) {
	srv, err := web.New(web.Config{
		Root:          root,
		DB:            db,
		SecureCookies: os.Getenv("PIT_INSECURE_COOKIES") != "1",
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := envOr("PIT_ADDR", ":8081")
	log.Printf("pit-web listening on %s, repos in %s", addr, root)
	if code := srv.SetupCode(); code != "" {
		log.Printf("FIRST RUN: no accounts exist yet. Open /setup and enter setup code: %s", code)
	}
	hs := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(hs.ListenAndServe())
}

func adopt(root string, db *store.Store, args []string) {
	if len(args) < 2 {
		log.Fatal("usage: pit-web adopt USER REPO... | pit-web adopt USER --all")
	}
	owner, ok := db.UserByName(args[0])
	if !ok {
		log.Fatalf("no such user %q (create the admin at /setup first)", args[0])
	}
	repos := args[1:]
	if len(repos) == 1 && repos[0] == "--all" {
		repos = nil
		ents, err := os.ReadDir(root)
		if err != nil {
			log.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() && objects.ValidName(e.Name()) {
				if _, claimed := db.RepoByName(e.Name()); !claimed {
					repos = append(repos, e.Name())
				}
			}
		}
	}
	for _, r := range repos {
		st, err := os.Stat(filepath.Join(root, r))
		switch {
		case !objects.ValidName(r) || err != nil || !st.IsDir():
			fmt.Printf("skip %s: not a repository in %s\n", r, root)
		default:
			if err := db.AddRepo(r, owner.ID, false); err != nil {
				fmt.Printf("skip %s: %v\n", r, err)
			} else {
				fmt.Printf("%s -> %s (private)\n", r, owner.Username)
			}
		}
	}
}

func resetPassword(db *store.Store, args []string) {
	if len(args) != 1 {
		log.Fatal("usage: pit-web reset-password USER")
	}
	u, ok := db.UserByName(args[0])
	if !ok {
		log.Fatalf("no such user %q", args[0])
	}
	pw := auth.RandomString(20)
	hash, err := auth.HashPassword(pw)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.SetPassword(u.ID, hash); err != nil {
		log.Fatal(err)
	}
	db.DeleteUserSessions(u.ID, "")
	fmt.Printf("temporary password for %s: %s\nLog in and change it under Settings.\n", u.Username, pw)
}
