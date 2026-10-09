package utils

import (
	"strings"
	"testing"
	"time"
)

func init() { Iterations = 1000 }

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("correct horse battery", h) || CheckPassword("wrong", h) || CheckPassword("", h) {
		t.Fatal("password check wrong")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "x", "pbkdf2-sha256$1$a$b", "pbkdf2-sha256$99999999999$AAAA$AAAA", "md5$1$a$b"} {
		if CheckPassword("x", bad) {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if ValidPassword("short") == nil || ValidPassword(strings.Repeat("a", 257)) == nil || ValidPassword("long enough pw") != nil {
		t.Fatal("policy wrong")
	}
}

func TestSecrets(t *testing.T) {
	tok, h := NewAPIToken()
	if !strings.HasPrefix(tok, "pit_") || Hash(tok) != h || len(tok) != 68 {
		t.Fatalf("token %q", tok)
	}
	a, _ := NewSessionID()
	b, _ := NewSessionID()
	if a == b || len(a) < 40 {
		t.Fatal("session ids not random enough")
	}
	if len(RandomString(20)) != 20 {
		t.Fatal("RandomString length")
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewRateLimiter(3, time.Minute)
	l.Now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		l.Fail("k")
	}
	if !l.Allow("k") {
		t.Fatal("blocked too early")
	}
	l.Fail("k")
	if l.Allow("k") || !l.Allow("other") {
		t.Fatal("limit not applied per key")
	}
	now = now.Add(61 * time.Second)
	if !l.Allow("k") {
		t.Fatal("still blocked after window")
	}
	l.Fail("k")
	l.Reset("k")
	l.Fail("k")
	l.Fail("k")
	if !l.Allow("k") {
		t.Fatal("Reset did not clear failures")
	}
}
