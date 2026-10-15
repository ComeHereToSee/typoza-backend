package merge

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func lines(ls ...string) []byte {
	return []byte(strings.Join(ls, "\n") + "\n")
}

func TestMerge3(t *testing.T) {
	base := lines("a", "b", "c", "d", "e", "f", "g")
	cases := []struct {
		name         string
		ours, theirs []byte
		want         []byte // nil 表示应合并失败
	}{
		{"不重叠修改", lines("a", "B", "c", "d", "e", "f", "g"), lines("a", "b", "c", "d", "e", "F", "g"),
			lines("a", "B", "c", "d", "e", "F", "g")},
		{"重叠修改", lines("a", "b", "X", "d", "e", "f", "g"), lines("a", "b", "Y", "d", "e", "f", "g"), nil},
		{"相邻行修改视为重叠", lines("a", "B", "c", "d", "e", "f", "g"), lines("a", "b", "C", "d", "e", "f", "g"), nil},
		{"双方相同修改", lines("a", "b", "Z", "d", "e", "f", "g"), lines("a", "b", "Z", "d", "e", "f", "g"),
			lines("a", "b", "Z", "d", "e", "f", "g")},
		{"只有一侧修改", base, lines("a", "b", "c", "d", "e", "f", "g", "h"), lines("a", "b", "c", "d", "e", "f", "g", "h")},
		{"首尾插入", lines("top", "a", "b", "c", "d", "e", "f", "g"), lines("a", "b", "c", "d", "e", "f", "g", "bottom"),
			lines("top", "a", "b", "c", "d", "e", "f", "g", "bottom")},
		{"删除与远处修改", lines("a", "c", "d", "e", "f", "g"), lines("a", "b", "c", "d", "e", "f", "G"),
			lines("a", "c", "d", "e", "f", "G")},
		{"同一位置插入不同内容", lines("a", "b", "c", "x", "d", "e", "f", "g"), lines("a", "b", "c", "y", "d", "e", "f", "g"), nil},
		{"一侧删除一侧修改同一行", lines("a", "b", "d", "e", "f", "g"), lines("a", "b", "C", "d", "e", "f", "g"), nil},
	}
	for _, c := range cases {
		got, ok := Merge3(base, c.ours, c.theirs)
		if c.want == nil {
			if ok {
				t.Errorf("%s: 应合并失败,得到 %q", c.name, got)
			}
			continue
		}
		if !ok || string(got) != string(c.want) {
			t.Errorf("%s: got %q ok=%v, want %q", c.name, got, ok, c.want)
		}
	}
}

func TestMerge3_EdgeCases(t *testing.T) {
	// 空基线:双方新增相同内容可合并,不同内容冲突。
	if got, ok := Merge3(nil, []byte("x\n"), []byte("x\n")); !ok || string(got) != "x\n" {
		t.Fatalf("空基线相同内容: %q %v", got, ok)
	}
	if _, ok := Merge3(nil, []byte("x\n"), []byte("y\n")); ok {
		t.Fatal("空基线不同内容应冲突")
	}
	// 一侧清空、另一侧未改:结果为空。
	base := lines("a", "b")
	if got, ok := Merge3(base, nil, base); !ok || len(got) != 0 {
		t.Fatalf("一侧清空: %q %v", got, ok)
	}
	// 末尾无换行的行也能参与合并。
	base = []byte("1\n2\n3\n4\n5")
	ours := []byte("one\n2\n3\n4\n5")
	theirs := []byte("1\n2\n3\n4\n5!")
	if got, ok := Merge3(base, ours, theirs); !ok || string(got) != "one\n2\n3\n4\n5!" {
		t.Fatalf("末行无换行: %q %v", got, ok)
	}
	// CRLF 行尾原样保留。
	base = []byte("a\r\nb\r\nc\r\nd\r\n")
	ours = []byte("A\r\nb\r\nc\r\nd\r\n")
	theirs = []byte("a\r\nb\r\nc\r\nD\r\n")
	if got, ok := Merge3(base, ours, theirs); !ok || string(got) != "A\r\nb\r\nc\r\nD\r\n" {
		t.Fatalf("CRLF: %q %v", got, ok)
	}
}

func TestMerge3_TooManyEdits(t *testing.T) {
	var b, o, th strings.Builder
	for i := 0; i < MaxEdits+10; i++ {
		b.WriteString("base\n")
		o.WriteString("ours\n")
		th.WriteString("base\n")
	}
	th.WriteString("tail\n")
	if _, ok := Merge3([]byte(b.String()), []byte(o.String()), []byte(th.String())); ok {
		t.Fatal("差异超过 MaxEdits 应放弃合并")
	}
}

// lcsLen 是 O(nm) 动态规划求最长公共子序列长度,作为 Myers 实现的对照。
func lcsLen(x, y []int) int {
	dp := make([][]int, len(x)+1)
	for i := range dp {
		dp[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	return dp[0][0]
}

func TestMatchIsLongestCommonSubsequence(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for iter := 0; iter < 500; iter++ {
		x := make([]int, r.IntN(30))
		y := make([]int, r.IntN(30))
		for i := range x {
			x[i] = r.IntN(4)
		}
		for i := range y {
			y[i] = r.IntN(4)
		}
		m, ok := match(x, y)
		if !ok {
			t.Fatalf("match 失败: %v %v", x, y)
		}
		count, last := 0, -1
		for i, j := range m {
			if j < 0 {
				continue
			}
			if j <= last || j >= len(y) || x[i] != y[j] {
				t.Fatalf("匹配非法 x=%v y=%v m=%v", x, y, m)
			}
			last = j
			count++
		}
		if want := lcsLen(x, y); count != want {
			t.Fatalf("LCS 长度 %d, want %d (x=%v y=%v m=%v)", count, want, x, y, m)
		}
	}
}
