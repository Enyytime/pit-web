package models

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "db.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestUsersAndPersistence(t *testing.T) {
	s, p := open(t)
	u, err := s.CreateFirstAdmin("Kenny", "hash")
	if err != nil || !u.IsAdmin {
		t.Fatal(err)
	}
	if _, err := s.CreateFirstAdmin("other", "h"); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("second first-admin: %v", err)
	}
	if got, ok := s.UserByName("kenny"); !ok || got.ID != u.ID {
		t.Fatal("case-insensitive lookup failed")
	}
	if _, err := s.RedeemInvite("nope", "bob", "h"); !errors.Is(err, ErrBadInvite) {
		t.Fatalf("bad invite: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("db file mode %v, want 0600", st.Mode().Perm())
	}
	s2, err := Open(p)
	if err != nil || s2.UserCount() != 1 {
		t.Fatalf("reopen: %v", err)
	}
}

func TestInviteRedeem(t *testing.T) {
	s, _ := open(t)
	admin, _ := s.CreateFirstAdmin("admin", "h")
	if _, err := s.CreateInvite("inv1", "for bob", admin.ID, s.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateInvite("inv2", "expired", admin.ID, s.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemInvite("inv2", "late", "h"); !errors.Is(err, ErrBadInvite) {
		t.Fatalf("expired invite accepted: %v", err)
	}
	// A taken username must not burn the invite.
	if _, err := s.RedeemInvite("inv1", "ADMIN", "h"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := s.RedeemInvite("inv1", "bad name!", "h"); !errors.Is(err, ErrBadName) {
		t.Fatalf("bad name: %v", err)
	}
	if _, err := s.RedeemInvite("inv1", "bob", "h"); err != nil {
		t.Fatalf("invite was consumed by failed attempts: %v", err)
	}
	if _, err := s.RedeemInvite("inv1", "bob2", "h"); !errors.Is(err, ErrBadInvite) {
		t.Fatal("invite reusable")
	}
}

func TestSessionsAndTokens(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(5000, 0)
	s.Now = func() time.Time { return now }
	u, _ := s.CreateFirstAdmin("alice", "h")
	s.CreateSession(Session{Hash: "s1", UserID: u.ID, CSRF: "c", Expires: now.Add(time.Hour)})
	s.CreateSession(Session{Hash: "s2", UserID: u.ID, CSRF: "c", Expires: now.Add(time.Hour)})
	if _, _, ok := s.SessionByHash("s1"); !ok {
		t.Fatal("session missing")
	}
	s.DeleteUserSessions(u.ID, "s2")
	if _, _, ok := s.SessionByHash("s1"); ok {
		t.Fatal("session survived DeleteUserSessions")
	}
	if _, _, ok := s.SessionByHash("s2"); !ok {
		t.Fatal("excepted session was deleted")
	}
	now = now.Add(2 * time.Hour)
	if _, _, ok := s.SessionByHash("s2"); ok {
		t.Fatal("expired session accepted")
	}

	tok, err := s.CreateToken(u.ID, "laptop", "th", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.TokenByHash("th"); !ok {
		t.Fatal("token missing")
	}
	if err := s.DeleteToken(u.ID+99, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted someone else's token")
	}
	if err := s.DeleteToken(u.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateToken(u.ID, "  ", "x", false); err == nil {
		t.Fatal("blank token name accepted")
	}
}

// The admin CLI is a second process (here: a second Store) writing the same file.
func TestCrossProcessWrites(t *testing.T) {
	a, p := open(t)
	a.CreateFirstAdmin("admin", "h")
	b, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddRepo("demo", 1, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.RepoByName("demo"); !ok {
		t.Fatal("server did not see the CLI's write")
	}
	// And the server's next write must not clobber the CLI's.
	a.AddRepo("other", 1, true)
	if _, ok := b.RepoByName("other"); !ok {
		t.Fatal("CLI did not see the server's write")
	}
	if len(a.ListRepos()) != 2 {
		t.Fatalf("lost update: %v", a.ListRepos())
	}
}

func TestCorruptFileIsNotOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db.json")
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := Open(p); err == nil {
		t.Fatal("corrupt file accepted")
	}
	if b, _ := os.ReadFile(p); string(b) != "{not json" {
		t.Fatal("corrupt file was modified")
	}
}
