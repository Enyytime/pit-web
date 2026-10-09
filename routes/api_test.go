package routes_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Enyytime/pit-web/models"
	"github.com/Enyytime/pit-web/utils"
)

func init() { log.SetOutput(io.Discard) } // the server logs every push; keep test output clean

// ---------- helpers: build objects the way the pit client uploads them ----------

// enc returns an object's hash and its zlib-compressed file bytes.
func enc(typ string, body []byte) (string, []byte) {
	full := append([]byte(fmt.Sprintf("%s %d\x00", typ, len(body))), body...)
	sum := sha1.Sum(full)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write(full)
	zw.Close()
	return hex.EncodeToString(sum[:]), buf.Bytes()
}

func treeBody(es ...te) []byte {
	var b bytes.Buffer
	for _, e := range es {
		raw, _ := hex.DecodeString(e.hash)
		fmt.Fprintf(&b, "%s %s\x00", e.mode, e.name)
		b.Write(raw)
	}
	return b.Bytes()
}

func commitBody(tree, parent, msg string) []byte {
	s := "tree " + tree + "\n"
	if parent != "" {
		s += "parent " + parent + "\n"
	}
	return []byte(s + "author Bob <b@example.com> 1791120640 +0000\ncommitter Bob <b@example.com> 1791120640 +0000\n\n" + msg + "\n")
}

// token mints an API token for u directly in the store.
func (e *env) token(u models.User, write bool) string {
	e.t.Helper()
	tok, h := utils.NewAPIToken()
	if _, err := e.db.CreateToken(u.ID, "test", h, write); err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (c *client) put(path string, body []byte, user, tok string) resp {
	c.t.Helper()
	req, _ := http.NewRequest("PUT", c.base+path, bytes.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, tok)
	}
	return c.do(req)
}

// push uploads one commit (a single file) the way `pit push` does: objects first, then the ref.
type pushed struct{ blob, tree, commit string }

func (c *client) push(t *testing.T, repo, branch, user, tok, filename, content, parent string) pushed {
	t.Helper()
	var p pushed
	var z []byte
	p.blob, z = enc("blob", []byte(content))
	mustOK(t, c.put("/"+repo+"/objects/"+p.blob, z, user, tok), "blob")
	var tz []byte
	p.tree, tz = enc("tree", treeBody(te{"100644", filename, p.blob}))
	mustOK(t, c.put("/"+repo+"/objects/"+p.tree, tz, user, tok), "tree")
	var cz []byte
	p.commit, cz = enc("commit", commitBody(p.tree, parent, "commit of "+filename))
	mustOK(t, c.put("/"+repo+"/objects/"+p.commit, cz, user, tok), "commit")
	mustOK(t, c.put("/"+repo+"/refs/"+branch, []byte(p.commit+"\n"), user, tok), "ref")
	return p
}

func mustOK(t *testing.T, r resp, what string) {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("%s: status %d: %s", what, r.code, r.body)
	}
}

func code(t *testing.T, r resp, want int, what string) {
	t.Helper()
	if r.code != want {
		t.Errorf("%s: status %d, want %d (%s)", what, r.code, want, strings.TrimSpace(r.body))
	}
}

// ---------- tests ----------

func TestAPIPushCreatesRepoAndPullReadsIt(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	alice := e.addUser("alice", "alices long password", false)
	rw, ro := e.token(bob, true), e.token(bob, false)
	aliceRW := e.token(alice, true)
	c := e.client()

	// A brand-new repo does not exist yet: the client's first reads fail, which it tolerates.
	code(t, c.basic("/proj/objects", "bob", rw), 404, "list before push")
	code(t, c.basic("/proj/refs/main", "bob", rw), 404, "ref before push")

	p := c.push(t, "proj", "main", "bob", rw, "hello.txt", "hi there\n", "")

	rp, ok := e.db.RepoByName("proj")
	if !ok || rp.OwnerID != bob.ID || rp.Public {
		t.Fatalf("pushed repo should be bob's and private: %+v %v", rp, ok)
	}
	list := c.basic("/proj/objects", "bob", rw)
	code(t, list, 200, "list")
	for _, h := range []string{p.blob, p.tree, p.commit} {
		if !strings.Contains(list.body, h) {
			t.Errorf("object list is missing %s", h)
		}
	}
	// What the client downloads is byte-for-byte what was uploaded.
	_, z := enc("blob", []byte("hi there\n"))
	if got := c.basic("/proj/objects/"+p.blob, "bob", ro); got.code != 200 || got.body != string(z) {
		t.Fatalf("downloaded object differs (status %d)", got.code)
	}
	if got := c.basic("/proj/refs/main", "bob", ro); got.code != 200 || strings.TrimSpace(got.body) != p.commit {
		t.Fatalf("ref: %d %q", got.code, got.body)
	}

	// The web viewer sees the pushed repo and its commit.
	bc := e.client()
	bc.mustLogin("bob", "bobs long password")
	has(t, bc.get("/r/proj/main"), "commit of hello.txt")

	// Other accounts: private repo is invisible, and cannot be written to.
	anon := e.client()
	r := anon.get("/proj/objects")
	code(t, r, 401, "anonymous list of private repo")
	if r.hdr.Get("WWW-Authenticate") == "" {
		t.Error("401 without a Basic challenge")
	}
	code(t, c.basic("/proj/objects", "alice", aliceRW), 404, "alice reading bob's private repo")
	code(t, c.put("/proj/refs/main", []byte(p.commit), "alice", aliceRW), 403, "alice writing bob's repo")
	_, z2 := enc("blob", []byte("sneaky"))
	h2, _ := enc("blob", []byte("sneaky"))
	code(t, c.put("/proj/objects/"+h2, z2, "alice", aliceRW), 403, "alice uploading to bob's repo")

	// Read-only token cannot push; session cookies cannot push at all.
	code(t, c.put("/proj/objects/"+h2, z2, "bob", ro), 403, "read-only token PUT")
	code(t, bc.put("/proj/objects/"+h2, z2, "", ""), 401, "cookie-session PUT")
	if _, err := os.Stat(filepath.Join(e.root, "proj", "objects", h2[:2], h2[2:])); err == nil {
		t.Fatal("a rejected upload was written to disk")
	}
	// Token with someone else's username is refused outright.
	code(t, c.put("/proj/objects/"+h2, z2, "kenny", rw), 401, "token with wrong username")
}

func TestAPIPublicRepoAnonymousPull(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	rw := e.token(bob, true)
	c := e.client()
	p := c.push(t, "open", "main", "bob", rw, "a.txt", "x\n", "")

	code(t, c.get("/open/refs/main"), 401, "anonymous before it is public")
	e.db.SetRepoPublic("open", true)
	code(t, c.get("/open/objects"), 200, "anonymous list")
	code(t, c.get("/open/objects/"+p.blob), 200, "anonymous object")
	if r := c.get("/open/refs/main"); r.code != 200 || strings.TrimSpace(r.body) != p.commit {
		t.Fatalf("anonymous ref: %d %q", r.code, r.body)
	}
	code(t, c.put("/open/refs/main", []byte(p.commit), "", ""), 401, "anonymous push to a public repo")
	code(t, c.get("/open/objects/"+strings.Repeat("0", 40)), 404, "missing object")
}

func TestAPIObjectValidation(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	rw := e.token(bob, true)
	c := e.client()

	h, z := enc("blob", []byte("real content\n"))
	other, _ := enc("blob", []byte("something else\n"))
	path := func(h string) string { return "/val/objects/" + h }

	code(t, c.put(path(other), z, "bob", rw), 400, "object uploaded under the wrong hash")
	code(t, c.put(path(h), []byte("this is not zlib"), "bob", rw), 400, "garbage body")
	code(t, c.put(path(h), append(append([]byte{}, z...), []byte("trailing junk")...), "bob", rw), 400, "trailing data")

	// A header that lies about the size, with a hash computed over the lie.
	bad := []byte("blob 99\x00short")
	sum := sha1.Sum(bad)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write(bad)
	zw.Close()
	code(t, c.put(path(hex.EncodeToString(sum[:])), buf.Bytes(), "bob", rw), 400, "size/header mismatch")

	weird := []byte("tag 3\x00abc")
	sum = sha1.Sum(weird)
	buf.Reset()
	zw = zlib.NewWriter(&buf)
	zw.Write(weird)
	zw.Close()
	code(t, c.put(path(hex.EncodeToString(sum[:])), buf.Bytes(), "bob", rw), 400, "unknown object type")

	if e.db.ListRepos() != nil {
		t.Fatal("a repo was created by uploads that all failed validation")
	}
	code(t, c.put(path(h), z, "bob", rw), 200, "valid object")
	code(t, c.put(path(h), z, "bob", rw), 200, "uploading the same object twice")

	// Malformed routes never reach a handler.
	code(t, c.put("/val/objects/NOTAHASH", z, "bob", rw), 404, "bad hash in path")
	// The router cleans ".." paths with a redirect before any handler runs.
	// The redirect status differs between Go versions (301, 307, 308), so
	// accept any redirect or a 404; what matters is that it is never a success.
	switch r := c.put("/val/refs/..", z, "bob", rw); r.code {
	case 301, 302, 307, 308, 404:
	default:
		t.Errorf("traversal ref name: status %d", r.code)
	}
	code(t, c.put("/val/refs/.hidden", z, "bob", rw), 404, "hidden ref name")
	code(t, c.put("/val/objects", z, "bob", rw), 400, "PUT to the object list")
	code(t, c.put("/admin/objects/"+h, z, "bob", rw), 404, "reserved repo name")
	code(t, c.get("/login/objects"), 404, "reserved repo name on GET")

	req, _ := http.NewRequest("DELETE", c.base+"/val/objects/"+h, nil)
	req.SetBasicAuth("bob", rw)
	code(t, c.do(req), 405, "DELETE")
}

func TestAPIRefRules(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	rw := e.token(bob, true)
	c := e.client()

	first := c.push(t, "rr", "main", "bob", rw, "a.txt", "one\n", "")

	// A ref cannot point at something that was never uploaded.
	missing := strings.Repeat("a", 40)
	code(t, c.put("/rr/refs/main", []byte(missing), "bob", rw), 400, "ref to unknown commit")
	code(t, c.put("/rr/refs/main", []byte("not a hash"), "bob", rw), 400, "ref that is not a hash")
	code(t, c.put("/rr/refs/main", []byte(first.blob), "bob", rw), 400, "ref pointing at a blob")

	// A commit whose file was never uploaded is rejected as an incomplete push.
	ghost := strings.Repeat("b", 40)
	tr, trz := enc("tree", treeBody(te{"100644", "ghost.txt", ghost}))
	mustOK(t, c.put("/rr/objects/"+tr, trz, "bob", rw), "tree with missing blob")
	cm, cmz := enc("commit", commitBody(tr, first.commit, "incomplete"))
	mustOK(t, c.put("/rr/objects/"+cm, cmz, "bob", rw), "commit")
	code(t, c.put("/rr/refs/main", []byte(cm), "bob", rw), 409, "incomplete push")
	if got := c.basic("/rr/refs/main", "bob", rw); strings.TrimSpace(got.body) != first.commit {
		t.Fatal("branch moved despite the failed update")
	}

	// A normal fast-forward works; pushing the same commit again is a no-op.
	second := c.push(t, "rr", "main", "bob", rw, "b.txt", "two\n", first.commit)
	code(t, c.put("/rr/refs/main", []byte(second.commit), "bob", rw), 200, "idempotent ref update")

	// Rewriting history (a commit that is not a descendant) is refused.
	diverged := c.push(t, "rr", "side", "bob", rw, "c.txt", "diverged\n", "")
	code(t, c.put("/rr/refs/main", []byte(diverged.commit), "bob", rw), 409, "non-fast-forward")
	code(t, c.put("/rr/refs/main", []byte(first.commit), "bob", rw), 409, "moving the branch backwards")
	if got := c.basic("/rr/refs/main", "bob", rw); strings.TrimSpace(got.body) != second.commit {
		t.Fatalf("branch changed by rejected updates: %q", got.body)
	}
	// A different branch can point anywhere that exists.
	code(t, c.put("/rr/refs/other", []byte(first.commit), "bob", rw), 200, "new branch")

	// Pushing a ref to a repo that doesn't exist must not create it.
	code(t, c.put("/nope/refs/main", []byte(first.commit), "bob", rw), 400, "ref to a non-existent repo")
	if _, ok := e.db.RepoByName("nope"); ok {
		t.Fatal("repo created by a ref PUT")
	}
}

func TestAPILegacyReposAndQuota(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	adminTok := e.token(models.User{ID: 1}, true)
	rw := e.token(bob, true)
	c := e.client()
	e.mkrepo("legacy") // exists on disk, owned by nobody

	h, z := enc("blob", []byte("x"))
	code(t, c.put("/legacy/objects/"+h, z, "bob", rw), 403, "non-admin writing an unowned legacy repo")
	code(t, c.put("/legacy/objects/"+h, z, "kenny", adminTok), 200, "admin writing an unowned legacy repo")
	if _, ok := e.db.RepoByName("legacy"); ok {
		t.Fatal("writing to a legacy repo should not silently claim it")
	}

	// Repo creation is capped per account.
	for i := 0; i < 50; i++ {
		code(t, c.put(fmt.Sprintf("/repo%d/objects/%s", i, h), z, "bob", rw), 200, fmt.Sprintf("create repo %d", i))
	}
	code(t, c.put("/repo50/objects/"+h, z, "bob", rw), 403, "51st repository")
	code(t, c.put("/repo0/objects/"+h, z, "bob", rw), 200, "existing repos still writable at the cap")
}

func TestAPIAdminCanWriteAnyOwnedRepo(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	bobTok, adminTok := e.token(bob, true), e.token(admin, true)
	c := e.client()
	c.push(t, "bobs", "main", "bob", bobTok, "a.txt", "one\n", "")
	h, z := enc("blob", []byte("admin was here\n"))
	code(t, c.put("/bobs/objects/"+h, z, "kenny", adminTok), 200, "admin uploading to bob's repo")
}

func TestAPIUploadSizeLimit(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	bob := e.addUser("bob", "bobs long password", false)
	rw := e.token(bob, true)
	c := e.client()
	h, _ := enc("blob", []byte("x"))
	big := bytes.Repeat([]byte("A"), 65<<20)
	code(t, c.put("/big/objects/"+h, big, "bob", rw), 413, "65 MB upload")
	if _, ok := e.db.RepoByName("big"); ok {
		t.Fatal("repo created by an oversized upload")
	}
}

func TestSettingsShowsRemoteCommand(t *testing.T) {
	e := newEnv(t)
	e.addUser("kenny", "a long password", true)
	c := e.client()
	c.mustLogin("kenny", "a long password")
	r := c.postForm("/settings", "/settings/tokens", url.Values{"name": {"laptop"}, "scope": {"write"}})
	has(t, r, "pit remote add origin http://kenny:pit_", "@127.0.0.1:", "/REPONAME")
	if !strings.Contains(c.get("/settings").body, "read/write") {
		t.Fatal("token scope not shown in the list")
	}
}
