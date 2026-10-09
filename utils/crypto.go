package utils

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Iterations is the PBKDF2-HMAC-SHA256 work factor for new password hashes
// (OWASP's 2023 recommendation). Tests lower it; stored hashes record their own.
var Iterations = 600_000

const (
	MinPassword = 10
	MaxPassword = 256
	maxIter     = 10_000_000
)

var b64 = base64.RawStdEncoding

// ValidPassword enforces the password policy.
func ValidPassword(pw string) error {
	if len(pw) < MinPassword {
		return fmt.Errorf("password must be at least %d characters", MinPassword)
	}
	if len(pw) > MaxPassword {
		return fmt.Errorf("password must be at most %d characters", MaxPassword)
	}
	return nil
}

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<key>".
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// CheckPassword verifies pw against a hash produced by HashPassword.
func CheckPassword(pw, enc string) bool {
	p := strings.Split(enc, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1 || iter > maxIter {
		return false
	}
	salt, err1 := b64.DecodeString(p[2])
	want, err2 := b64.DecodeString(p[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// CheckAgainstDummy burns the same CPU as a real check, so a login attempt for
// an unknown username takes as long as one for a real username.
func CheckAgainstDummy(pw string) {
	dummyOnce.Do(func() { dummyHash, _ = HashPassword("dummy password for timing") })
	CheckPassword(pw, dummyHash)
}

// Hash returns the hex SHA-256 of s. Used for high-entropy secrets (session
// ids, API tokens, invite codes) where a slow hash is unnecessary.
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// NewSessionID returns a cookie value and the hash that is stored server-side.
func NewSessionID() (id, hash string) {
	id = base64.RawURLEncoding.EncodeToString(randBytes(32))
	return id, Hash(id)
}

// NewAPIToken returns a "pit_..." token and the hash that is stored.
func NewAPIToken() (token, hash string) {
	token = "pit_" + hex.EncodeToString(randBytes(32))
	return token, Hash(token)
}

// NewInviteCode returns a signup invite code and the hash that is stored.
func NewInviteCode() (code, hash string) {
	code = base64.RawURLEncoding.EncodeToString(randBytes(18))
	return code, Hash(code)
}

const alnum = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RandomString returns n random characters (no look-alike characters).
func RandomString(n int) string {
	b := randBytes(n)
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// Equal compares two secrets in constant time.
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ErrLimited is returned by callers when RateLimiter.Allow is false.
var ErrLimited = errors.New("too many attempts")

// RateLimiter blocks a key for Window after Max failures within Window.
type RateLimiter struct {
	Max    int
	Window time.Duration
	Now    func() time.Time

	mu sync.Mutex
	m  map[string]*limitEntry
}

type limitEntry struct {
	fails       int
	first, lock time.Time
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{Max: max, Window: window, Now: time.Now, m: map[string]*limitEntry{}}
}

// Allow reports whether key may attempt now.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	return e == nil || !l.Now().Before(e.lock)
}

// Fail records a failed attempt.
func (l *RateLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	if len(l.m) > 10000 {
		for k, e := range l.m {
			if now.Sub(e.first) > l.Window && !now.Before(e.lock) {
				delete(l.m, k)
			}
		}
	}
	e := l.m[key]
	if e == nil || now.Sub(e.first) > l.Window {
		e = &limitEntry{first: now}
		l.m[key] = e
	}
	e.fails++
	if e.fails >= l.Max {
		e.lock = now.Add(l.Window)
	}
}

// Reset clears key after a successful attempt.
func (l *RateLimiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
