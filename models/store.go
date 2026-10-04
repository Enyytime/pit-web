// Package models holds the data types and keeps accounts, sessions, API tokens, repo ownership and
// invites in one JSON file. Writes are atomic (temp file + rename) and are
// serialised across processes with flock, and every operation re-reads the
// file if another process (e.g. the admin CLI) changed it, so the CLI can be
// used while the server runs. It is sized for a personal forge, not millions
// of users; the exported methods are the seam where SQLite could replace it.
package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)


var (
	ErrExists    = errors.New("already exists")
	ErrNotFound  = errors.New("not found")
	ErrBadInvite = errors.New("invalid or expired invite")
	ErrNotEmpty  = errors.New("users already exist")
	ErrBadName   = errors.New("username must be 2-32 characters: letters, digits, _ . -")
	ErrLimit     = errors.New("limit reached")
)

var userRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{1,31}$`)

// ValidUsername reports whether s is an acceptable username.
func ValidUsername(s string) bool { return userRe.MatchString(s) }

const maxTokensPerUser = 20

type User struct {
	ID       int64     `json:"id"`
	Username string    `json:"username"`
	PassHash string    `json:"pass_hash"`
	IsAdmin  bool      `json:"is_admin"`
	Created  time.Time `json:"created"`
}

type Session struct {
	Hash    string    `json:"hash"`
	UserID  int64     `json:"user_id"`
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

type Token struct {
	ID       int64     `json:"id"`
	UserID   int64     `json:"user_id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Write    bool      `json:"write"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used"`
}

type Repo struct {
	Name    string    `json:"name"`
	OwnerID int64     `json:"owner_id"`
	Public  bool      `json:"public"`
	Created time.Time `json:"created"`
}

type Invite struct {
	ID        int64     `json:"id"`
	Hash      string    `json:"hash"`
	Note      string    `json:"note"`
	CreatedBy int64     `json:"created_by"`
	Expires   time.Time `json:"expires"`
}

type data struct {
	NextID   int64     `json:"next_id"`
	Users    []User    `json:"users"`
	Sessions []Session `json:"sessions"`
	Tokens   []Token   `json:"tokens"`
	Repos    []Repo    `json:"repos"`
	Invites  []Invite  `json:"invites"`
}