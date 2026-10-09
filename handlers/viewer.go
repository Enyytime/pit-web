package handlers

import (
	"fmt"
	"github.com/Enyytime/pit-web/middleware"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Enyytime/pit-web/utils"
)

const (
	perPage      = 50        // commits per page in the log
	maxWalk      = 5000      // hard cap on commits walked (guards against cycles)
	maxViewBytes = 1 << 20   // blobs larger than this are truncated in the viewer
	maxDiffBytes = 512 << 10 // blobs larger than this are not diffed
	maxDiffFiles = 200       // files shown with a full diff per commit
	ctxLines     = 3         // unchanged lines of context around a change
)

func esc(s string) string { return html.EscapeString(s) }

// pathParam returns the optional ?p= display path (breadcrumb / filename).
func pathParam(r *http.Request) string {
	p := r.URL.Query().Get("p")
	if len(p) > 512 || !utf8.ValidString(p) {
		return ""
	}
	return p
}

func pq(p string) string {
	if p == "" {
		return ""
	}
	return "?p=" + url.QueryEscape(p)
}

func badge(public bool, claimed bool) string {
	switch {
	case !claimed:
		return `<span class=badge>unclaimed</span>`
	case public:
		return `<span class="badge pub">public</span>`
	}
	return `<span class=badge>private</span>`
}

func (s *App) Home(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DB.UserCount() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	a := middleware.Who(r)
	ents, _ := os.ReadDir(s.cfg.Root)
	var sb strings.Builder
	sb.WriteString("<h3>Repositories</h3>")
	n := 0
	for _, e := range ents {
		if !e.IsDir() || !utils.ValidName(e.Name()) || !s.canView(a.User, e.Name()) {
			continue
		}
		n++
		rp, claimed := s.cfg.DB.RepoByName(e.Name())
		owner := ""
		if claimed {
			if u, ok := s.cfg.DB.UserByID(rp.OwnerID); ok {
				owner = " · " + esc(u.Username)
			}
		}
		fmt.Fprintf(&sb, `<div class=c><a href="/r/%s">%s</a> %s<span class=m>%s</span></div>`,
			esc(e.Name()), esc(e.Name()), badge(rp.Public, claimed), owner)
	}
	if n == 0 {
		if a.User == nil {
			sb.WriteString(`<div class=m>No public repositories. <a href="/login">Log in</a> to see yours.</div>`)
		} else {
			sb.WriteString(`<div class=m>No repositories yet.</div>`)
		}
	}
	s.viewer(w, r, "pit", sb.String())
}

func (s *App) ListBranches(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	ents, err := os.ReadDir(filepath.Join(s.cfg.Root, repo, "refs"))
	if err != nil {
		notFound(w)
		return
	}
	a := middleware.Who(r)
	rp, claimed := s.cfg.DB.RepoByName(repo)
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s %s</h3>", esc(repo), badge(rp.Public, claimed))
	for _, e := range ents {
		if utils.ValidName(e.Name()) {
			fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/%s">%s</a></div>`, esc(repo), esc(e.Name()), esc(e.Name()))
		}
	}
	if claimed && a.Sess != nil && s.canManage(a.User, repo) {
		want, label := "1", "Make public"
		if rp.Public {
			want, label = "0", "Make private"
		}
		fmt.Fprintf(&sb, `<form method=post action="/r/%s/visibility" class=inline><input type=hidden name=csrf value="%s"><input type=hidden name=public value="%s"><button>%s</button></form>`,
			esc(repo), esc(a.Sess.CSRF), want, label)
	}
	s.viewer(w, r, repo+" · pit", sb.String())
}

func (s *App) SetVisibility(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requirePost(w, r)
	if !ok {
		return
	}
	repo := r.PathValue("repo")
	if !utils.ValidName(repo) || !s.canManage(a.User, repo) {
		notFound(w)
		return
	}
	if err := s.cfg.DB.SetRepoPublic(repo, r.PostFormValue("public") == "1"); err != nil {
		notFound(w)
		return
	}
	http.Redirect(w, r, "/r/"+url.PathEscape(repo), http.StatusSeeOther)
}

func (s *App) CommitLog(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	branch := r.PathValue("branch")
	if !utils.ValidName(branch) {
		notFound(w)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.Root, repo, "refs", branch))
	if err != nil {
		notFound(w)
		return
	}
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	skip := (pg - 1) * perPage

	h := strings.TrimSpace(string(b))
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s / %s</h3>", esc(repo), esc(branch))
	shown, more := 0, false
	for n := 0; utils.ValidHash(h) && n < maxWalk; n++ {
		_, body, err := s.obj.Read(repo, h)
		if err != nil {
			break
		}
		f, msg := utils.ParseCommit(body)
		if n >= skip {
			if shown == perPage {
				more = true
				break
			}
			first, _, _ := strings.Cut(msg, "\n")
			if first == "" {
				first = "(no message)"
			}
			name, when := utils.AuthorInfo(f["author"])
			fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/commit/%s">%s</a><div class=m>%s · %s · %s · <a href="/r/%s/tree/%s">files</a></div></div>`,
				esc(repo), h, esc(first), h[:8], esc(name), when, esc(repo), esc(f["tree"]))
			shown++
		}
		h = f["parent"]
	}
	if shown == 0 && pg > 1 {
		notFound(w)
		return
	}
	sb.WriteString("<div class=nav><span>")
	if pg > 1 {
		fmt.Fprintf(&sb, `<a href="/r/%s/%s?page=%d">← newer</a>`, esc(repo), esc(branch), pg-1)
	}
	sb.WriteString("</span><span>")
	if more {
		fmt.Fprintf(&sb, `<a href="/r/%s/%s?page=%d">older →</a>`, esc(repo), esc(branch), pg+1)
	}
	sb.WriteString("</span></div>")
	s.viewer(w, r, repo+"/"+branch+" · pit", sb.String())
}

func (s *App) ShowCommit(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	h := r.PathValue("hash")
	if !utils.ValidHash(h) {
		notFound(w)
		return
	}
	typ, body, err := s.obj.Read(repo, h)
	if err != nil || typ != "commit" {
		notFound(w)
		return
	}
	f, msg := utils.ParseCommit(body)
	if !utils.ValidHash(f["tree"]) {
		notFound(w)
		return
	}
	name, when := utils.AuthorInfo(f["author"])

	newFiles := map[string]string{}
	if err := s.obj.Flatten(repo, f["tree"], "", 0, newFiles); err != nil {
		http.Error(w, "cannot read tree: "+err.Error(), http.StatusInternalServerError)
		return
	}
	oldFiles := map[string]string{}
	parent := f["parent"]
	if utils.ValidHash(parent) {
		if pt, err := s.obj.CommitTree(repo, parent); err == nil {
			if err := s.obj.Flatten(repo, pt, "", 0, oldFiles); err != nil {
				http.Error(w, "cannot read parent tree: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	seen := map[string]bool{}
	var paths []string
	for p := range newFiles {
		seen[p] = true
		paths = append(paths, p)
	}
	for p := range oldFiles {
		if !seen[p] {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	var sb strings.Builder
	first, _, _ := strings.Cut(msg, "\n")
	fmt.Fprintf(&sb, `<h3>%s</h3><div class=msg>%s</div>`, esc(first), esc(msg))
	fmt.Fprintf(&sb, `<div class=m>%s · %s · commit %s</div>`, esc(name), when, h)
	sb.WriteString("<div class=bar>")
	if utils.ValidHash(parent) {
		fmt.Fprintf(&sb, `<a href="/r/%s/commit/%s">← parent %s</a>`, esc(repo), parent, parent[:8])
	}
	fmt.Fprintf(&sb, `<a href="/r/%s/tree/%s">browse files</a></div>`, esc(repo), esc(f["tree"]))

	changed, shown := 0, 0
	var files strings.Builder
	for _, p := range paths {
		oh, nh := oldFiles[p], newFiles[p]
		if oh == nh {
			continue
		}
		changed++
		if shown >= maxDiffFiles {
			continue
		}
		shown++
		status := "M"
		switch {
		case oh == "":
			status = "A"
		case nh == "":
			status = "D"
		}
		fmt.Fprintf(&files, `<h4><span class=st>%s</span>%s</h4>`, status, esc(p))
		files.WriteString(s.diffBlobs(repo, oh, nh))
	}
	fmt.Fprintf(&sb, `<div class=m>%d file(s) changed</div>`, changed)
	sb.WriteString(files.String())
	if changed > shown {
		fmt.Fprintf(&sb, `<div class=m>%d more changed files not shown</div>`, changed-shown)
	}
	s.viewer(w, r, first+" · pit", sb.String())
}

// diffBlobs renders the diff between two blob hashes ("" means absent).
func (s *App) diffBlobs(repo, oh, nh string) string {
	read := func(h string) ([]byte, string) {
		if h == "" {
			return nil, ""
		}
		typ, b, err := s.obj.Read(repo, h)
		if err != nil || typ != "blob" {
			return nil, "unreadable object"
		}
		if len(b) > maxDiffBytes {
			return nil, "file too large to diff"
		}
		if utils.IsBinary(b) {
			return nil, "binary file"
		}
		return b, ""
	}
	a, why := read(oh)
	if why == "" {
		var b []byte
		b, why = read(nh)
		if why == "" {
			ls, ok := utils.DiffLines(utils.SplitLines(string(a)), utils.SplitLines(string(b)))
			if !ok {
				why = "file too large to diff"
			} else {
				out, adds, dels := renderDiff(ls)
				return fmt.Sprintf(`<div class=m><span class=ad>+%d</span> <span class=de>-%d</span></div>%s`, adds, dels, out)
			}
		}
	}
	return `<div class=m>` + esc(why) + `</div>`
}

func num(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// renderDiff renders the changed lines with ctxLines of context, hiding the rest.
func renderDiff(ls []utils.DLine) (out string, adds, dels int) {
	keep := make([]bool, len(ls))
	for i, l := range ls {
		if l.Op == ' ' {
			continue
		}
		if l.Op == '+' {
			adds++
		} else {
			dels++
		}
		for k := i - ctxLines; k <= i+ctxLines; k++ {
			if k >= 0 && k < len(ls) {
				keep[k] = true
			}
		}
	}
	var sb strings.Builder
	sb.WriteString("<div class=diff>")
	gap := false
	for i, l := range ls {
		if !keep[i] {
			gap = true
			continue
		}
		if gap && i > 0 {
			sb.WriteString(`<div class=d><span class=n></span><span class=n></span><span class=h>…</span></div>`)
		}
		gap = false
		cls, sign := "", " "
		switch l.Op {
		case '+':
			cls, sign = " a", "+"
		case '-':
			cls, sign = " r", "-"
		}
		fmt.Fprintf(&sb, `<div class="d%s"><span class=n>%s</span><span class=n>%s</span>%s%s</div>`,
			cls, num(l.Old), num(l.New), sign, esc(l.Text))
	}
	sb.WriteString("</div>")
	return sb.String(), adds, dels
}

func (s *App) ShowTree(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	h := r.PathValue("hash")
	if !utils.ValidHash(h) {
		notFound(w)
		return
	}
	typ, body, err := s.obj.Read(repo, h)
	if err != nil || typ != "tree" {
		notFound(w)
		return
	}
	dir := pathParam(r)
	var sb strings.Builder
	crumb := esc(repo)
	if dir != "" {
		crumb += " / " + esc(strings.ReplaceAll(dir, "/", " / "))
	}
	fmt.Fprintf(&sb, "<h3>%s</h3>", crumb)

	ents := utils.ParseTree(body)
	sort.SliceStable(ents, func(i, j int) bool { // directories first
		return (ents[i].Mode == "40000") && (ents[j].Mode != "40000")
	})
	for _, e := range ents {
		full := e.Name
		if dir != "" {
			full = dir + "/" + e.Name
		}
		kind, slash := "blob", ""
		if e.Mode == "40000" {
			kind, slash = "tree", "/"
		}
		fmt.Fprintf(&sb, `<div class=c><a href="/r/%s/%s/%s%s">%s%s</a></div>`,
			esc(repo), kind, e.Hash, esc(pq(full)), esc(e.Name), slash)
	}
	s.viewer(w, r, repo+" · pit", sb.String())
}

func (s *App) ShowBlob(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	h := r.PathValue("hash")
	if !utils.ValidHash(h) {
		notFound(w)
		return
	}
	typ, body, err := s.obj.Read(repo, h)
	if err != nil || typ != "blob" {
		notFound(w)
		return
	}
	p := pathParam(r)
	title := p
	if title == "" {
		title = h[:8]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<h3>%s</h3>", esc(title))
	fmt.Fprintf(&sb, `<div class=bar><span class=m>%d bytes</span><a href="/r/%s/raw/%s%s">raw</a></div>`,
		len(body), esc(repo), h, esc(pq(p)))
	if utils.IsBinary(body) {
		sb.WriteString(`<div class=m>binary file — use the raw link to download it</div>`)
	} else {
		shown, note := body, ""
		if len(shown) > maxViewBytes {
			shown = shown[:maxViewBytes]
			for !utf8.Valid(shown) && len(shown) > 0 {
				shown = shown[:len(shown)-1]
			}
			note = `<div class=m>file truncated — use the raw link for the full content</div>`
		}
		sb.WriteString("<pre class=code>")
		for _, l := range utils.SplitLines(string(shown)) {
			sb.WriteString("<span class=l>" + esc(l) + "</span>\n")
		}
		sb.WriteString("</pre>" + note)
	}
	s.viewer(w, r, title+" · pit", sb.String())
}

func (s *App) RawBlob(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repoAccess(w, r)
	if !ok {
		return
	}
	h := r.PathValue("hash")
	if !utils.ValidHash(h) {
		notFound(w)
		return
	}
	typ, body, err := s.obj.Read(repo, h)
	if err != nil || typ != "blob" {
		notFound(w)
		return
	}
	ct := "text/plain; charset=utf-8"
	if utils.IsBinary(body) {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}
