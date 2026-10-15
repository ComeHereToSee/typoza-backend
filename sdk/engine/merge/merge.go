// Package merge 实现行级三方合并(diff3)。
//
// 用于同步冲突(sync-protocol §7.5):base 是上次同步的基线内容,ours 是本地修改,
// theirs 是远端新版本。两侧改动不重叠时自动合并;任何一处重叠(含相邻行改动)都判定失败,
// 由调用方另存冲突副本——宁可多出一个副本,也不能合错内容。
//
// 算法:先用 Myers 差分分别求 base↔ours、base↔theirs 的最长公共子序列匹配,
// 再按 Khanna、Kunal、Pierce《A Formal Investigation of Diff3》的方法切分稳定块与不稳定块。
package merge

import "bytes"

// MaxEdits 是单侧差分允许的最大编辑距离(按行)。超过时放弃合并,
// 避免两份差异巨大的文本在 Myers 算法上耗费 O(D²) 的内存与时间。
const MaxEdits = 2000

// Merge3 对 base、ours、theirs 做行级三方合并。
// ok=false 表示存在重叠修改或差异过大,调用方应走冲突副本流程。
func Merge3(base, ours, theirs []byte) (merged []byte, ok bool) {
	if bytes.Equal(ours, theirs) {
		return bytes.Clone(ours), true
	}
	if bytes.Equal(base, ours) {
		return bytes.Clone(theirs), true
	}
	if bytes.Equal(base, theirs) {
		return bytes.Clone(ours), true
	}

	in := newInterner()
	o := in.lines(base)
	a := in.lines(ours)
	b := in.lines(theirs)

	ma, okA := match(o.ids, a.ids)
	if !okA {
		return nil, false
	}
	mb, okB := match(o.ids, b.ids)
	if !okB {
		return nil, false
	}

	var out bytes.Buffer
	nO, nA, nB := len(o.ids), len(a.ids), len(b.ids)
	lo, la, lb := 0, 0, 0
	for {
		// 稳定块:三方逐行一致的连续区间。
		i := 0
		for lo+i < nO && ma[lo+i] == la+i && mb[lo+i] == lb+i {
			i++
		}
		if i > 0 {
			o.write(&out, lo, lo+i)
			lo, la, lb = lo+i, la+i, lb+i
		}
		if lo == nO && la == nA && lb == nB {
			break
		}
		// 不稳定块:找到下一行在两侧都有匹配的 base 行 j,之前的部分是一个冲突候选区。
		j := lo
		for j < nO && (ma[j] < 0 || mb[j] < 0) {
			j++
		}
		eo, ea, eb := nO, nA, nB
		if j < nO {
			eo, ea, eb = j, ma[j], mb[j]
		}
		switch {
		case equalIDs(a.ids[la:ea], o.ids[lo:eo]):
			// 只有 theirs 改了这一段。
			b.write(&out, lb, eb)
		case equalIDs(b.ids[lb:eb], o.ids[lo:eo]):
			// 只有 ours 改了这一段。
			a.write(&out, la, ea)
		case equalIDs(a.ids[la:ea], b.ids[lb:eb]):
			// 两侧做了相同的修改。
			a.write(&out, la, ea)
		default:
			return nil, false
		}
		lo, la, lb = eo, ea, eb
	}
	return out.Bytes(), true
}

// text 是按行切分后的文本:ids 是行内容的整数编号,lines 保留原始字节(含行尾换行符)。
type text struct {
	ids   []int
	lines [][]byte
}

func (t text) write(buf *bytes.Buffer, from, to int) {
	for _, l := range t.lines[from:to] {
		buf.Write(l)
	}
}

// interner 给相同内容的行分配相同编号,差分时只比较整数。
type interner struct {
	ids map[string]int
}

func newInterner() *interner { return &interner{ids: make(map[string]int)} }

// lines 按 '\n' 切行,每行保留自己的换行符;最后一行可以没有换行符,
// 这样「末尾有无换行」也会被当作内容差异参与合并,不会被悄悄抹平。
func (in *interner) lines(data []byte) text {
	var t text
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n') + 1
		if n == 0 {
			n = len(data)
		}
		line := data[:n]
		id, ok := in.ids[string(line)]
		if !ok {
			id = len(in.ids)
			in.ids[string(line)] = id
		}
		t.ids = append(t.ids, id)
		t.lines = append(t.lines, line)
		data = data[n:]
	}
	return t
}

func equalIDs(x, y []int) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// match 求 x 与 y 的最长公共子序列匹配:返回 m,m[i] 是 x[i] 在 y 中匹配的下标,未匹配为 -1。
// 匹配单调递增。编辑距离超过 MaxEdits 时 ok=false。
func match(x, y []int) (m []int, ok bool) {
	m = make([]int, len(x))
	for i := range m {
		m[i] = -1
	}
	// 先剥掉公共前缀与后缀:日常编辑通常集中在局部,剥掉后 Myers 只需处理很小的中段。
	pre := 0
	for pre < len(x) && pre < len(y) && x[pre] == y[pre] {
		m[pre] = pre
		pre++
	}
	suf := 0
	for suf < len(x)-pre && suf < len(y)-pre && x[len(x)-1-suf] == y[len(y)-1-suf] {
		m[len(x)-1-suf] = len(y) - 1 - suf
		suf++
	}
	mid, ok := myers(x[pre:len(x)-suf], y[pre:len(y)-suf])
	if !ok {
		return nil, false
	}
	for i, j := range mid {
		if j >= 0 {
			m[pre+i] = pre + j
		}
	}
	return m, true
}

// myers 是 Myers O(ND) 差分(贪心找最短编辑脚本),保存每一步的 V 窗口用于回溯。
// 内存 O(D²),由 MaxEdits 限定上界。
func myers(x, y []int) ([]int, bool) {
	n, m := len(x), len(y)
	res := make([]int, n)
	for i := range res {
		res[i] = -1
	}
	if n == 0 || m == 0 {
		return res, true
	}
	maxD := n + m
	if maxD > MaxEdits {
		maxD = MaxEdits
	}
	off := n + m + 1
	v := make([]int, 2*(n+m)+3)
	// trace[d] 保存第 d 步结束后 v[-d..d] 的快照(下标 k+d)。
	var trace [][]int
	for d := 0; d <= maxD; d++ {
		for k := -d; k <= d; k += 2 {
			var px int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				px = v[off+k+1] // 下移:y 方向插入
			} else {
				px = v[off+k-1] + 1 // 右移:x 方向删除
			}
			py := px - k
			for px < n && py < m && x[px] == y[py] {
				px++
				py++
			}
			v[off+k] = px
			if px >= n && py >= m {
				trace = append(trace, append([]int(nil), v[off-d:off+d+1]...))
				backtrack(trace, res, n, m)
				return res, true
			}
		}
		trace = append(trace, append([]int(nil), v[off-d:off+d+1]...))
	}
	return nil, false
}

// backtrack 从终点沿 trace 倒推,把每段对角线(相同行)写入 res。
func backtrack(trace [][]int, res []int, n, m int) {
	x, y := n, m
	for d := len(trace) - 1; d > 0; d-- {
		prev := trace[d-1]
		get := func(k int) int { return prev[k+d-1] }
		k := x - y
		var pk int
		if k == -d || (k != d && get(k-1) < get(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := get(pk)
		py := px - pk
		// 本步编辑之后、对角线起点的 x 坐标。
		sx := px
		if pk == k-1 {
			sx = px + 1
		}
		for x > sx {
			x--
			y--
			res[x] = y
		}
		x, y = px, py
	}
	for x > 0 && y > 0 {
		x--
		y--
		res[x] = y
	}
}
