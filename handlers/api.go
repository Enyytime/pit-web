package handlers

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Enyytime/pit-web/middleware"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Enyytime/pit-web/utils"
)

// The push/pull API is the wire protocol the pit client speaks (it replaces
// pit-server.py). The remote URL is https://USER:TOKEN@HOST/REPO and the client
// appends:
//
//	GET /REPO/objects          newline-separated hashes of every object
//	GET /REPO/objects/HASH     the stored (zlib-compressed) object file
//	PUT /REPO/objects/HASH     upload an object
//	GET /REPO/refs/BRANCH      the commit hash a branch points to
//	PUT /REPO/refs/BRANCH      move a branch (fast-forward only)
//
// Reads follow the same rules as the viewer (public repos need no credentials).
// Writes need an API token with write access to a repo you own; pushing to a
// name nobody has used creates that repo, owned by you and private.

const (
	maxPutBytes     = 64 << 20 // largest accepted upload (compressed)
	maxObjectBytes  = 64 << 20 // largest accepted object once decompressed
	maxReposPerUser = 50       // repos one account may create by pushing
	maxFFWalk       = 50000    // commits walked to prove a push is a fast-forward
)

// reservedNames cannot be used as repo names over the API, because their first
// path segment belongs to the website.
var reservedNames = map[string]bool{
	"r": true, "api": true, "login": true, "logout": true, "setup": true,
	"signup": true, "settings": true, "admin": true, "static": true, "favicon.ico": true,
}

func parseAPIPath(p string) (repo, kind, arg string, ok bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 2 || !utils.ValidName(parts[0]) || reservedNames[parts[0]] {
		return
	}
	repo = parts[0]
	switch {
	case parts[1] == "objects" && len(parts) == 2:
		return repo, "list", "", true
	case parts[1] == "objects" && len(parts) == 3 && utils.ValidHash(parts[2]):
		return repo, "obj", parts[2], true
	case parts[1] == "refs" && len(parts) == 3 && utils.ValidName(parts[2]):
		return repo, "ref", parts[2], true
	}
	return "", "", "", false
}

// API handles every path the website doesn't claim: the pit client API.
func (s *App) API(w http.ResponseWriter, r *http.Request) {
	repo, kind, arg, ok := parseAPIPath(r.URL.Path)
	if !ok {
		notFound(w)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.apiGet(w, r, repo, kind, arg)
	case http.MethodPut:
		s.apiPut(w, r, repo, kind, arg)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="pit", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (s *App) objPath(repo, h string) string {
	return filepath.Join(s.cfg.Root, repo, "objects", h[:2], h[2:])
}

func (s *App) refPath(repo, branch string) string {
	return filepath.Join(s.cfg.Root, repo, "refs", branch)
}

func (s *App) apiGet(w http.ResponseWriter, r *http.Request, repo, kind, arg string) {
	a := middleware.Who(r)
	if !s.canView(a.User, repo) {
		if a.User == nil {
			challenge(w)
			return
		}
		notFound(w) // private and missing look the same
		return
	}
	if !dirExists(filepath.Join(s.cfg.Root, repo)) {
		notFound(w)
		return
	}
	switch kind {
	case "list":
		base := filepath.Join(s.cfg.Root, repo, "objects")
		var sb strings.Builder
		dirs, _ := os.ReadDir(base)
		for _, d := range dirs {
			if !d.IsDir() || len(d.Name()) != 2 {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(base, d.Name()))
			for _, f := range files {
				if h := d.Name() + f.Name(); utils.ValidHash(h) {
					sb.WriteString(h + "\n")
				}
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, sb.String())
	case "obj":
		f, err := os.Open(s.objPath(repo, arg))
		if err != nil {
			notFound(w)
			return
		}
		defer f.Close()
		if st, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
	case "ref":
		b, err := os.ReadFile(s.refPath(repo, arg))
		if err != nil {
			notFound(w)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	}
}

const noWrite = "no write access to this repository (the name may already be taken)"

// writeAccess decides whether user may write to repo. creating is true when
// the repo does not exist yet and this write would create it.
func (s *App) writeAccess(userID int64, admin bool, repo string) (creating bool, code int, msg string) {
	if rp, claimed := s.cfg.DB.RepoByName(repo); claimed {
		if admin || rp.OwnerID == userID {
			return false, 0, ""
		}
		return false, http.StatusForbidden, noWrite
	}
	if dirExists(filepath.Join(s.cfg.Root, repo)) { // predates accounts and has no owner
		if admin {
			return false, 0, ""
		}
		return false, http.StatusForbidden, "this repository has no owner yet; ask an admin to assign it"
	}
	owned := 0
	for _, rp := range s.cfg.DB.ListRepos() {
		if rp.OwnerID == userID {
			owned++
		}
	}
	if owned >= maxReposPerUser {
		return false, http.StatusForbidden, "repository limit reached"
	}
	return true, 0, ""
}

func (s *App) apiPut(w http.ResponseWriter, r *http.Request, repo, kind, arg string) {
	a := middleware.Who(r)
	// Writes are API-token only: a browser session cookie must never be able
	// to push (that would open the door to cross-site request forgery).
	if a.Token == nil {
		challenge(w)
		return
	}
	if !a.Token.Write {
		http.Error(w, "this token is read-only; create a read/write token in Settings", http.StatusForbidden)
		return
	}
	if kind == "list" {
		http.Error(w, "cannot PUT the object list", http.StatusBadRequest)
		return
	}
	creating, code, msg := s.writeAccess(a.User.ID, a.User.IsAdmin, repo)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	if kind == "obj" {
		if _, err := os.Stat(s.objPath(repo, arg)); err == nil {
			w.WriteHeader(http.StatusOK) // already have it
			return
		}
	}
	if kind == "ref" && creating {
		http.Error(w, "push objects before moving a branch", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPutBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read body", http.StatusBadRequest)
		}
		return
	}

	var newRef string
	switch kind {
	case "obj":
		if code, msg := verifyObject(arg, body); code != 0 {
			http.Error(w, msg, code)
			return
		}
	case "ref":
		newRef = strings.TrimSpace(string(body))
		if !utils.ValidHash(newRef) {
			http.Error(w, "a ref must contain a 40-character commit hash", http.StatusBadRequest)
			return
		}
	}

	if creating {
		if err := s.cfg.DB.AddRepo(repo, a.User.ID, false); err != nil {
			// Lost a race with another creator: re-check who owns it now.
			if _, code, msg := s.writeAccess(a.User.ID, a.User.IsAdmin, repo); code != 0 {
				http.Error(w, msg, code)
				return
			}
		} else {
			log.Printf("api: %s created repository %s", a.User.Username, repo)
		}
	}

	switch kind {
	case "obj":
		if err := atomicWrite(s.objPath(repo, arg), body); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
	case "ref":
		s.pushMu.Lock()
		defer s.pushMu.Unlock()
		if code, msg := s.checkRefUpdate(repo, arg, newRef); code != 0 {
			http.Error(w, msg, code)
			return
		}
		if err := atomicWrite(s.refPath(repo, arg), body); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		log.Printf("api: %s moved %s/%s to %s", a.User.Username, repo, arg, newRef)
	}
	w.WriteHeader(http.StatusOK)
}

// verifyObject checks that body is a well-formed zlib-compressed pit object
// whose SHA-1 really is name. Without this, any writer could plant junk under
// the hash of a commit that has not been pushed yet.
func verifyObject(name string, body []byte) (int, string) {
	br := bytes.NewReader(body)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return http.StatusBadRequest, "not a zlib stream"
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, maxObjectBytes+1))
	if err != nil {
		return http.StatusBadRequest, "corrupt zlib data"
	}
	if len(data) > maxObjectBytes {
		return http.StatusRequestEntityTooLarge, "object too large"
	}
	if br.Len() != 0 {
		return http.StatusBadRequest, "unexpected data after the compressed object"
	}
	i := bytes.IndexByte(data, 0)
	if i < 0 {
		return http.StatusBadRequest, "object has no header"
	}
	var typ string
	var size int
	if _, err := fmt.Sscanf(string(data[:i]), "%s %d", &typ, &size); err != nil {
		return http.StatusBadRequest, "malformed object header"
	}
	if typ != "blob" && typ != "tree" && typ != "commit" {
		return http.StatusBadRequest, "unknown object type"
	}
	if size != len(data)-i-1 {
		return http.StatusBadRequest, "object size does not match its header"
	}
	if sum := sha1.Sum(data); hex.EncodeToString(sum[:]) != name {
		return http.StatusBadRequest, "object content does not match its hash"
	}
	return 0, ""
}

// checkRefUpdate enforces, on the server, the rules the client only checks
// politely: the target is a real commit, everything it needs has been
// uploaded, and the branch only ever moves forward. The caller holds pushMu.
func (s *App) checkRefUpdate(repo, branch, newHash string) (int, string) {
	typ, body, err := s.obj.Read(repo, newHash)
	if err != nil || typ != "commit" {
		return http.StatusBadRequest, "that commit has not been uploaded"
	}
	f, _ := utils.ParseCommit(body)
	if !utils.ValidHash(f["tree"]) {
		return http.StatusBadRequest, "commit has no valid tree"
	}
	files := map[string]string{}
	if err := s.obj.Flatten(repo, f["tree"], "", 0, files); err != nil {
		return http.StatusConflict, "incomplete push: " + err.Error()
	}
	for _, h := range files {
		if _, err := os.Stat(s.objPath(repo, h)); err != nil {
			return http.StatusConflict, "incomplete push: a file the commit needs was not uploaded"
		}
	}
	cur, err := os.ReadFile(s.refPath(repo, branch))
	if err != nil {
		return 0, "" // new branch
	}
	curHash := strings.TrimSpace(string(cur))
	if !utils.ValidHash(curHash) || curHash == newHash {
		return 0, ""
	}
	for h, n := newHash, 0; utils.ValidHash(h) && n < maxFFWalk; n++ {
		if h == curHash {
			return 0, ""
		}
		_, b, err := s.obj.Read(repo, h)
		if err != nil {
			break
		}
		pf, _ := utils.ParseCommit(b)
		h = pf["parent"]
	}
	return http.StatusConflict, "not a fast-forward: the branch has commits you don't have (pull first)"
}

// atomicWrite writes data to path via a temp file in the same directory, so a
// reader never sees a half-written object or ref.
func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp." + utils.RandomString(8)
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
