// Objects: reads pit's on-disk object format (zlib-compressed
// "<type> <size>\0<content>" files named by SHA-1) and computes line diffs.
package utils

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxDepth     = 32        // directory nesting limit when flattening a tree
	MaxFiles     = 20000     // files per tree when flattening
	MaxDiffCells = 4_000_000 // LCS table size limit per file
)

var (
	// names can't start with "." so ".." and hidden dirs are rejected
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ValidName reports whether s is a safe repo or branch name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidHash reports whether s is a 40-char lowercase hex SHA-1.
func ValidHash(s string) bool { return hashRe.MatchString(s) }

// ObjectStore reads objects from <Root>/<repo>/objects/.
type ObjectStore struct{ Root string }

type Entry struct{ Mode, Name, Hash string }

// Read loads and decompresses object h of repo, returning its type and body.
func (s ObjectStore) Read(repo, h string) (string, []byte, error) {
	if !ValidName(repo) || !ValidHash(h) {
		return "", nil, fmt.Errorf("invalid repo or hash")
	}
	f, err := os.Open(filepath.Join(s.Root, repo, "objects", h[:2], h[2:]))
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

// ParseTree decodes "<mode> <name>\0<20 raw bytes>" entries.
func ParseTree(b []byte) []Entry {
	var out []Entry
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
		out = append(out, Entry{string(b[:sp]), string(b[sp+1 : nul]), hex.EncodeToString(b[nul+1 : nul+21])})
		b = b[nul+21:]
	}
	return out
}

// ParseCommit splits a commit into header fields and message.
func ParseCommit(b []byte) (map[string]string, string) {
	head, msg, _ := strings.Cut(string(b), "\n\n")
	f := map[string]string{}
	for _, line := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(line, " ")
		f[k] = v
	}
	return f, strings.TrimSpace(msg)
}

// AuthorInfo splits "Name <email> <ts> +0000" into a name and a formatted time.
func AuthorInfo(author string) (name, when string) {
	n, _, _ := strings.Cut(author, "<")
	name = strings.TrimSpace(n)
	if p := strings.Fields(author); len(p) >= 2 {
		if ts, err := strconv.ParseInt(p[len(p)-2], 10, 64); err == nil {
			when = time.Unix(ts, 0).UTC().Format("2006-01-02 15:04")
		}
	}
	return
}

// Flatten walks a tree recursively, filling out with path -> blob hash.
func (s ObjectStore) Flatten(repo, h, prefix string, depth int, out map[string]string) error {
	if depth > MaxDepth {
		return fmt.Errorf("tree too deep")
	}
	typ, body, err := s.Read(repo, h)
	if err != nil {
		return err
	}
	if typ != "tree" {
		return fmt.Errorf("%s is not a tree", h)
	}
	for _, e := range ParseTree(body) {
		p := prefix + e.Name
		if e.Mode == "40000" {
			if err := s.Flatten(repo, e.Hash, p+"/", depth+1, out); err != nil {
				return err
			}
			continue
		}
		out[p] = e.Hash
		if len(out) > MaxFiles {
			return fmt.Errorf("too many files")
		}
	}
	return nil
}

// CommitTree returns the tree hash recorded in commit h.
func (s ObjectStore) CommitTree(repo, h string) (string, error) {
	typ, body, err := s.Read(repo, h)
	if err != nil {
		return "", err
	}
	if typ != "commit" {
		return "", fmt.Errorf("%s is not a commit", h)
	}
	f, _ := ParseCommit(body)
	if !ValidHash(f["tree"]) {
		return "", fmt.Errorf("commit has no tree")
	}
	return f["tree"], nil
}

// IsBinary reports whether b looks like non-text content.
func IsBinary(b []byte) bool { return bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) }

// SplitLines splits s into lines, ignoring one trailing newline.
func SplitLines(s string) []string {
	if s == "" {
		return nil
	}
	ls := strings.Split(s, "\n")
	if ls[len(ls)-1] == "" {
		ls = ls[:len(ls)-1]
	}
	return ls
}

// DLine is one line of a diff.
type DLine struct {
	Op       byte // ' ', '+' or '-'
	Old, New int  // 1-based line numbers; 0 where not applicable
	Text     string
}

// DiffLines computes a line diff of a against b using an LCS table.
// It reports false if the inputs are too large to diff.
func DiffLines(a, b []string) ([]DLine, bool) {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	am, bm := a[pre:len(a)-suf], b[pre:len(b)-suf]
	n, m := len(am), len(bm)
	if n*m > MaxDiffCells {
		return nil, false
	}
	w := m + 1
	t := make([]int32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case am[i] == bm[j]:
				t[i*w+j] = t[(i+1)*w+j+1] + 1
			case t[(i+1)*w+j] >= t[i*w+j+1]:
				t[i*w+j] = t[(i+1)*w+j]
			default:
				t[i*w+j] = t[i*w+j+1]
			}
		}
	}

	var out []DLine
	o, nw := 1, 1
	emit := func(op byte, s string) {
		l := DLine{Op: op, Text: s}
		switch op {
		case ' ':
			l.Old, l.New = o, nw
			o++
			nw++
		case '-':
			l.Old = o
			o++
		case '+':
			l.New = nw
			nw++
		}
		out = append(out, l)
	}
	for i := 0; i < pre; i++ {
		emit(' ', a[i])
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case am[i] == bm[j]:
			emit(' ', am[i])
			i++
			j++
		case t[(i+1)*w+j] >= t[i*w+j+1]:
			emit('-', am[i])
			i++
		default:
			emit('+', bm[j])
			j++
		}
	}
	for ; i < n; i++ {
		emit('-', am[i])
	}
	for ; j < m; j++ {
		emit('+', bm[j])
	}
	for k := len(a) - suf; k < len(a); k++ {
		emit(' ', a[k])
	}
	return out, true
}
