package main

import (
	"bytes"
	"compress/zlib"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	root   string
	tokens []string
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type entry struct{ mode, name, hash string }

func readObj(repo, h string) (string, []byte, error) {
	f, err := os.Open(filepath.Join(root, repo, "objects", h[:2], h[2:]))
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	zr, err := zlib.NewReader(f)
	if err != nil {
		return "", nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return "", nil, err
	}
	i := bytes.IndexByte(raw, 0)
	if i < 0 {
		return "", nil, fmt.Errorf("malformed object")
	}
	hdr := strings.Fields(string(raw[:i]))
	if len(hdr) == 0 {
		return "", nil, fmt.Errorf("malformed object header")
	}
	return hdr[0], raw[i+1:], nil
}

func parseTree(b []byte) []entry {
	var out []entry
	for len(b) > 0 {
		sp := bytes.IndexByte(b, ' ')
		if sp < 0 {
			break
		}
		nul := bytes.IndexByte(b[sp:], 0)
		if nul < 0 {
			break
		}
		nul += sp
		if len(b) < nul+21 {
			break
		}
		out = append(out, entry{string(b[:sp]), string(b[sp+1 : nul]), hex.EncodeToString(b[nul+1 : nul+21])})
		b = b[nul+21:]
	}
	return out
}

func parseCommit(b []byte) (map[string]string, string) {
	head, msg, _ := strings.Cut(string(b), "\n\n")
	f := map[string]string{}
	for _, line := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(line, " ")
		f[k] = v
	}
	return f, strings.TrimSpace(msg)
}

const pageHead = `<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>pit</title>
<style>
body{font:15px system-ui;max-width:800px;margin:2rem auto;padding:0 1rem}
a{color:#0969da;text-decoration:none}
pre{background:#f6f8fa;padding:1rem;overflow:auto}
.c{border-bottom:1px solid #ddd;padding:.6rem 0}
.m{color:#666;font-size:13px}
@media(prefers-color-scheme:dark){
body{background:#0d1117;color:#e6edf3}pre{background:#161b22}
.c{border-color:#30363d}.m{color:#8b949e}a{color:#58a6ff}}
</style>
<h2><a href="/">pit</a></h2>`

func page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, pageHead+body)
}

func esc(s string) string { return html.EscapeString(s) }

func notFound(w http.ResponseWriter) { http.Error(w, "not found", http.StatusNotFound) }

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pw, ok := r.BasicAuth(); ok {
			for _, t := range tokens {
				if subtle.ConstantTimeCompare([]byte(pw), []byte(t)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="pit"`)
		http.Error(w, "login required", http.StatusUnauthorized)
	})
}

func listRepos(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		notFound(w)
		return
	}
	ents, _ := os.ReadDir(root)
	var sb strings.Builder
	sb.WriteString("<h3>Repositories</h3>")
	for _, e := range ents {
		if e.IsDir() && nameRe.MatchString(e.Name()) {
			fmt.Fprintf(&sb, `<div class=c><a href="/r/%s">%s</a></div>`, esc(e.Name()), esc(e.Name()))
		}
	}
	page(w, sb.String())
}

func listBranches(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	if !nameRe.MatchString(repo) {
		notFound(w)
		return
	}
	ents, err := os.ReadDir(filepath.Join(root, repo, "refs"))
	if err != nil {
		notFound(w)
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s</h3>", esc(repo))
	for _, e := range ents {
		if nameRe.MatchString(e.Name()) {
			fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/%s">%s</a></div>`, esc(repo), esc(e.Name()), esc(e.Name()))
		}
	}
	page(w, sb.String())
}

func commitLog(w http.ResponseWriter, r *http.Request) {
	repo, branch := r.PathValue("repo"), r.PathValue("branch")
	if !nameRe.MatchString(repo) || !nameRe.MatchString(branch) {
		notFound(w)
		return
	}
	b, err := os.ReadFile(filepath.Join(root, repo, "refs", branch))
	if err != nil {
		notFound(w)
		return
	}
	h := strings.TrimSpace(string(b))
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s / %s</h3>", esc(repo), esc(branch))
	for n := 0; hashRe.MatchString(h) && n < 500; n++ {
		_, body, err := readObj(repo, h)
		if err != nil {
			break
		}
		f, msg := parseCommit(body)
		first, _, _ := strings.Cut(msg, "\n")
		if first == "" {
			first = "(no message)"
		}
		author := f["author"]
		name, _, _ := strings.Cut(author, "<")
		when := ""
		if p := strings.Fields(author); len(p) >= 2 {
			if ts, err := strconv.ParseInt(p[len(p)-2], 10, 64); err == nil {
				when = time.Unix(ts, 0).UTC().Format("2006-01-02 15:04")
			}
		}
		fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/tree/%s">%s</a><div class=m>%s · %s · %s</div></div>`,
			esc(repo), esc(f["tree"]), esc(first), h[:8], esc(strings.TrimSpace(name)), when)
		h = f["parent"]
	}
	page(w, sb.String())
}

func showTree(w http.ResponseWriter, r *http.Request) {
	repo, h := r.PathValue("repo"), r.PathValue("hash")
	if !nameRe.MatchString(repo) || !hashRe.MatchString(h) {
		notFound(w)
		return
	}
	typ, body, err := readObj(repo, h)
	if err != nil || typ != "tree" {
		notFound(w)
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s</h3>", esc(repo))
	for _, e := range parseTree(body) {
		kind, slash := "blob", ""
		if e.mode == "40000" {
			kind, slash = "tree", "/"
		}
		fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/%s/%s">%s%s</a></div>`, esc(repo), kind, e.hash, esc(e.name), slash)
	}
	page(w, sb.String())
}

func showBlob(w http.ResponseWriter, r *http.Request) {
	repo, h := r.PathValue("repo"), r.PathValue("hash")
	if !nameRe.MatchString(repo) || !hashRe.MatchString(h) {
		notFound(w)
		return
	}
	typ, body, err := readObj(repo, h)
	if err != nil || typ != "blob" {
		notFound(w)
		return
	}
	page(w, "<pre>"+esc(string(body))+"</pre>")
}

func main() {
	home, _ := os.UserHomeDir()
	root = filepath.Join(home, "pit", "pit-data")
	data, err := os.ReadFile(filepath.Join(home, "pit", "pit-tokens.txt"))
	if err != nil {
		log.Fatalf("cannot read tokens: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if _, tok, ok := strings.Cut(line, ":"); ok {
			tokens = append(tokens, strings.TrimSpace(tok))
		}
	}
	sort.Strings(tokens)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", listRepos)
	mux.HandleFunc("GET /r/{repo}", listBranches)
	mux.HandleFunc("GET /r/{repo}/{branch}", commitLog)
	mux.HandleFunc("GET /r/{repo}/tree/{hash}", showTree)
	mux.HandleFunc("GET /r/{repo}/blob/{hash}", showBlob)

	addr := ":8081"
	log.Printf("pit-web listening on %s, data %s", addr, root)
	log.Fatal(http.ListenAndServe(addr, auth(mux)))
}
