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

type Store struct {
	Now func() time.Time

	mu   sync.Mutex
	path string
	d    data
	info os.FileInfo // identity of the file we last loaded or wrote
}

// Open loads path, or starts empty if it does not exist yet.
func Open(path string) (*Store, error) {
	s := &Store{Now: time.Now, path: path}
	s.d.NextID = 1
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.info = nil
		return nil
	}
	if err != nil {
		return err
	}
	var d data
	if len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("%s is corrupt: %w", s.path, err)
		}
	}
	if d.NextID < 1 {
		d.NextID = 1
	}
	s.d = d
	s.info, _ = os.Stat(s.path)
	return nil
}

// refresh reloads the file if another process replaced or changed it.
func (s *Store) refresh() error {
	cur, err := os.Stat(s.path)
	if err != nil {
		return nil // missing file: keep what we have
	}
	if s.info != nil && os.SameFile(s.info, cur) && cur.ModTime().Equal(s.info.ModTime()) && cur.Size() == s.info.Size() {
		return nil
	}
	return s.load()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.d, "", " ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", s.path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	s.info, _ = os.Stat(s.path)
	return nil
}

func (s *Store) flock() (func(), error) {
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// update runs fn under the in-process and cross-process locks and saves the
// result. fn must validate before it mutates, because an error return does not
// roll back (it only reloads from disk if saving failed).
func (s *Store) update(fn func(d *data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.flock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.refresh(); err != nil {
		return err
	}
	if err := fn(&s.d); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		s.load()
		return err
	}
	return nil
}

func (s *Store) view(fn func(d *data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	fn(&s.d)
}

// ---------- users ----------

func createUser(d *data, now time.Time, username, passHash string, admin bool) (User, error) {
	if !ValidUsername(username) {
		return User{}, ErrBadName
	}
	for _, u := range d.Users {
		if strings.EqualFold(u.Username, username) {
			return User{}, ErrExists
		}
	}
	u := User{ID: d.NextID, Username: username, PassHash: passHash, IsAdmin: admin, Created: now}
	d.NextID++
	d.Users = append(d.Users, u)
	return u, nil
}

func (s *Store) UserCount() (n int) {
	s.view(func(d *data) { n = len(d.Users) })
	return
}

// CreateFirstAdmin creates the initial admin, only if there are no users yet.
func (s *Store) CreateFirstAdmin(username, passHash string) (u User, err error) {
	err = s.update(func(d *data) error {
		if len(d.Users) > 0 {
			return ErrNotEmpty
		}
		u, err = createUser(d, s.Now(), username, passHash, true)
		return err
	})
	return
}

// RedeemInvite atomically consumes an invite and creates the user.
func (s *Store) RedeemInvite(inviteHash, username, passHash string) (u User, err error) {
	err = s.update(func(d *data) error {
		idx := -1
		for i, iv := range d.Invites {
			if iv.Hash == inviteHash && s.Now().Before(iv.Expires) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return ErrBadInvite
		}
		var cerr error
		// Validate and create first; only consume the invite if that worked.
		u, cerr = createUser(d, s.Now(), username, passHash, false)
		if cerr != nil {
			return cerr
		}
		d.Invites = append(d.Invites[:idx], d.Invites[idx+1:]...)
		return nil
	})
	return
}

func (s *Store) UserByName(name string) (u User, ok bool) {
	s.view(func(d *data) {
		for _, x := range d.Users {
			if strings.EqualFold(x.Username, name) {
				u, ok = x, true
				return
			}
		}
	})
	return
}

func (s *Store) UserByID(id int64) (u User, ok bool) {
	s.view(func(d *data) {
		for _, x := range d.Users {
			if x.ID == id {
				u, ok = x, true
				return
			}
		}
	})
	return
}

func (s *Store) ListUsers() (out []User) {
	s.view(func(d *data) { out = append(out, d.Users...) })
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return
}

// SetPassword replaces a user's password hash.
func (s *Store) SetPassword(userID int64, passHash string) error {
	return s.update(func(d *data) error {
		for i := range d.Users {
			if d.Users[i].ID == userID {
				d.Users[i].PassHash = passHash
				return nil
			}
		}
		return ErrNotFound
	})
}

// ---------- sessions ----------

// CreateSession stores a session and prunes expired sessions and invites.
func (s *Store) CreateSession(sess Session) error {
	return s.update(func(d *data) error {
		now := s.Now()
		keep := d.Sessions[:0]
		for _, x := range d.Sessions {
			if now.Before(x.Expires) {
				keep = append(keep, x)
			}
		}
		d.Sessions = append(keep, sess)
		inv := d.Invites[:0]
		for _, x := range d.Invites {
			if now.Before(x.Expires) {
				inv = append(inv, x)
			}
		}
		d.Invites = inv
		return nil
	})
}

func (s *Store) SessionByHash(hash string) (sess Session, u User, ok bool) {
	s.view(func(d *data) {
		for _, x := range d.Sessions {
			if x.Hash == hash && s.Now().Before(x.Expires) {
				for _, y := range d.Users {
					if y.ID == x.UserID {
						sess, u, ok = x, y, true
						return
					}
				}
			}
		}
	})
	return
}

func (s *Store) DeleteSession(hash string) error {
	return s.update(func(d *data) error {
		keep := d.Sessions[:0]
		for _, x := range d.Sessions {
			if x.Hash != hash {
				keep = append(keep, x)
			}
		}
		d.Sessions = keep
		return nil
	})
}

// DeleteUserSessions removes all of a user's sessions except the one with hash
// exceptHash (pass "" to remove them all).
func (s *Store) DeleteUserSessions(userID int64, exceptHash string) error {
	return s.update(func(d *data) error {
		keep := d.Sessions[:0]
		for _, x := range d.Sessions {
			if x.UserID != userID || (exceptHash != "" && x.Hash == exceptHash) {
				keep = append(keep, x)
			}
		}
		d.Sessions = keep
		return nil
	})
}

// ---------- API tokens ----------

func (s *Store) CreateToken(userID int64, name, hash string, write bool) (t Token, err error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return t, fmt.Errorf("token name must be 1-64 characters")
	}
	err = s.update(func(d *data) error {
		n := 0
		for _, x := range d.Tokens {
			if x.UserID == userID {
				n++
			}
		}
		if n >= maxTokensPerUser {
			return ErrLimit
		}
		t = Token{ID: d.NextID, UserID: userID, Name: name, Hash: hash, Write: write, Created: s.Now()}
		d.NextID++
		d.Tokens = append(d.Tokens, t)
		return nil
	})
	return
}

func (s *Store) TokenByHash(hash string) (t Token, u User, ok bool) {
	s.view(func(d *data) {
		for _, x := range d.Tokens {
			if x.Hash == hash {
				for _, y := range d.Users {
					if y.ID == x.UserID {
						t, u, ok = x, y, true
						return
					}
				}
			}
		}
	})
	return
}

// TouchToken records use at most once an hour, to avoid a disk write per request.
func (s *Store) TouchToken(id int64) {
	stale := false
	s.view(func(d *data) {
		for _, x := range d.Tokens {
			if x.ID == id {
				stale = s.Now().Sub(x.LastUsed) > time.Hour
			}
		}
	})
	if !stale {
		return
	}
	s.update(func(d *data) error {
		for i := range d.Tokens {
			if d.Tokens[i].ID == id {
				d.Tokens[i].LastUsed = s.Now()
			}
		}
		return nil
	})
}

func (s *Store) ListTokens(userID int64) (out []Token) {
	s.view(func(d *data) {
		for _, x := range d.Tokens {
			if x.UserID == userID {
				out = append(out, x)
			}
		}
	})
	return
}

func (s *Store) DeleteToken(userID, id int64) error {
	return s.update(func(d *data) error {
		for i, x := range d.Tokens {
			if x.ID == id && x.UserID == userID {
				d.Tokens = append(d.Tokens[:i], d.Tokens[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

// ---------- repos ----------

func (s *Store) AddRepo(name string, ownerID int64, public bool) error {
	return s.update(func(d *data) error {
		for _, r := range d.Repos {
			if r.Name == name {
				return ErrExists
			}
		}
		d.Repos = append(d.Repos, Repo{Name: name, OwnerID: ownerID, Public: public, Created: s.Now()})
		return nil
	})
}

func (s *Store) RepoByName(name string) (r Repo, ok bool) {
	s.view(func(d *data) {
		for _, x := range d.Repos {
			if x.Name == name {
				r, ok = x, true
				return
			}
		}
	})
	return
}

func (s *Store) SetRepoPublic(name string, public bool) error {
	return s.update(func(d *data) error {
		for i := range d.Repos {
			if d.Repos[i].Name == name {
				d.Repos[i].Public = public
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) ListRepos() (out []Repo) {
	s.view(func(d *data) { out = append(out, d.Repos...) })
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return
}

// ---------- invites ----------

const maxInvites = 100

func (s *Store) CreateInvite(hash, note string, createdBy int64, expires time.Time) (iv Invite, err error) {
	note = strings.TrimSpace(note)
	if len(note) > 100 {
		note = note[:100]
	}
	err = s.update(func(d *data) error {
		if len(d.Invites) >= maxInvites {
			return ErrLimit
		}
		iv = Invite{ID: d.NextID, Hash: hash, Note: note, CreatedBy: createdBy, Expires: expires}
		d.NextID++
		d.Invites = append(d.Invites, iv)
		return nil
	})
	return
}

func (s *Store) ListInvites() (out []Invite) {
	s.view(func(d *data) {
		for _, x := range d.Invites {
			if s.Now().Before(x.Expires) {
				out = append(out, x)
			}
		}
	})
	return
}

func (s *Store) DeleteInvite(id int64) error {
	return s.update(func(d *data) error {
		for i, x := range d.Invites {
			if x.ID == id {
				d.Invites = append(d.Invites[:i], d.Invites[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}
