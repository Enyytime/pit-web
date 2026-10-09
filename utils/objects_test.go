package utils

import (
	"fmt"
	"testing"
)

func TestDiffLines(t *testing.T) {
	ls, ok := DiffLines(SplitLines("a\nb\nc\nd\n"), SplitLines("a\nB\nc\nd\ne\n"))
	if !ok {
		t.Fatal("diff refused")
	}
	var got []string
	for _, l := range ls {
		got = append(got, string(l.Op)+l.Text)
	}
	if want := "[ a -b +B  c  d +e]"; fmt.Sprint(got) != want {
		t.Fatalf("got %v want %s", got, want)
	}
	if ls[1].Old != 2 || ls[2].New != 2 {
		t.Fatalf("bad line numbers: %+v %+v", ls[1], ls[2])
	}
}

func TestDiffEmptyIdenticalAndTooLarge(t *testing.T) {
	ls, _ := DiffLines(nil, SplitLines("x\ny\n"))
	if len(ls) != 2 || ls[0].Op != '+' {
		t.Fatalf("add-only diff wrong: %+v", ls)
	}
	ls, _ = DiffLines(SplitLines("x\n"), SplitLines("x\n"))
	if len(ls) != 1 || ls[0].Op != ' ' {
		t.Fatalf("identical diff wrong: %+v", ls)
	}
	big := make([]string, 3000)
	other := make([]string, 3000)
	for i := range big {
		big[i], other[i] = fmt.Sprint("a", i), fmt.Sprint("b", i)
	}
	if _, ok := DiffLines(big, other); ok {
		t.Fatal("expected refusal for huge diff")
	}
}

func TestValidators(t *testing.T) {
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", "a b", "../x"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidName("my-repo_1.git") || !ValidHash("0123456789abcdef0123456789abcdef01234567") || ValidHash("XYZ") {
		t.Error("validator regression")
	}
	if _, _, err := (ObjectStore{Root: t.TempDir()}).Read("../etc", "0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Error("Read accepted traversal")
	}
}
