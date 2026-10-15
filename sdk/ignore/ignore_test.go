package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltin(t *testing.T) {
	m := New(nil)
	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{".DS_Store", false, true},
		{"笔记/.DS_Store", false, true},
		{".typoza", true, true},
		{".typoza/state.db", false, true},
		{".git/config", false, true},
		{"sub/.git/HEAD", false, true},
		{"a.tmp", false, true},
		{"dir/.周报.md.typoza-123.tmp", false, true},
		{"~$报告.docx", false, true},
		{"笔记/周报.md", false, false},
		{".typoza", false, false}, // 同名普通文件不算目录规则
		{".gitignore", false, false},
		{"a.tmpl", false, false},
		{".typozaignore", false, false},
	}
	for _, c := range cases {
		if got := m.Match(c.path, c.isDir); got != c.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

func TestPatterns(t *testing.T) {
	m := New([]string{
		"# 注释行",
		"",
		"*.log",
		"build/",
		"/root-only.txt",
		"docs/**/draft-?.md",
		"**/cache",
		"assets/**",
		"空格 名字.md  ",
	})
	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"a.log", false, true},
		{"x/y/a.log", false, true},
		{"a.log.md", false, false},
		{"build", true, true},
		{"build/out.bin", false, true},
		{"src/build/out.bin", false, true},
		{"build", false, false}, // 名为 build 的文件不受目录规则影响
		{"root-only.txt", false, true},
		{"sub/root-only.txt", false, false},
		{"docs/draft-1.md", false, true},
		{"docs/a/b/draft-2.md", false, true},
		{"docs/draft-10.md", false, false},
		{"other/docs/draft-1.md", false, false},
		{"cache", true, true},
		{"a/b/cache/x", false, true},
		{"assets", true, true},
		{"assets/img/a.png", false, true},
		{"assetsX/a.png", false, false},
		{"空格 名字.md", false, true},
		{"# 注释行", false, false},
	}
	for _, c := range cases {
		if got := m.Match(c.path, c.isDir); got != c.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

func TestLiteralMetaChars(t *testing.T) {
	m := New([]string{"a+b(1).md", "[x].md", "!keep.md"})
	for _, p := range []string{"a+b(1).md", "[x].md", "!keep.md"} {
		if !m.Match(p, false) {
			t.Errorf("%q 应按字面匹配", p)
		}
	}
	if m.Match("aab(1).md", false) || m.Match("x.md", false) || m.Match("keep.md", false) {
		t.Error("正则元字符不应生效")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Match("a.md", false) || !m.Match(".DS_Store", false) {
		t.Fatal("无规则文件时只应有内置规则")
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("# c\r\n*.bak\r\nprivate/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("x.bak", false) || !m.Match("private/a.md", false) || m.Match("a.md", false) {
		t.Fatal(".typozaignore 规则未生效(含 CRLF 行尾)")
	}
}
