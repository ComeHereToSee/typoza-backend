// Package ignore 实现同步忽略规则(sync-protocol §7.8)。
//
// 规则来源:内置规则(.DS_Store、.typoza/、.git/、*.tmp、~$*)加库根目录 .typozaignore。
// .typozaignore 每行一个通配模式,支持 *、?、**,'#' 开头为注释,空行忽略。
//
// 匹配语义(取 gitignore 的常用子集,保持简单可预期):
//   - 模式以 '/' 结尾:只匹配目录(目录被忽略时其下所有内容一并忽略);
//   - 模式不含 '/'(结尾的除外):与任意层级的文件/目录名匹配;
//   - 模式含 '/':相对库根目录匹配完整路径,开头的 '/' 可省略;
//   - '*' 匹配除 '/' 外任意串,'?' 匹配除 '/' 外单个字符,'**' 跨目录匹配任意串;
//   - 不支持 '!' 取反与 [] 字符类,这些字符按字面匹配。
package ignore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FileName 是库根目录下的忽略规则文件名。
const FileName = ".typozaignore"

// Builtin 是内置忽略规则(协议 §7.8)。
var Builtin = []string{".DS_Store", ".typoza/", ".git/", "*.tmp", "~$*"}

type rule struct {
	re       *regexp.Regexp
	dirOnly  bool
	basename bool // 只与最后一段名字匹配
}

// Matcher 判断库内相对路径是否被忽略。零值不可用,用 New 或 Load 构造。
type Matcher struct {
	rules []rule
}

// New 用内置规则加上 patterns 构造 Matcher。patterns 的每一项按 .typozaignore 的一行解析。
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range append(append([]string(nil), Builtin...), patterns...) {
		if r, ok := compile(p); ok {
			m.rules = append(m.rules, r)
		}
	}
	return m
}

// Load 读取 root/.typozaignore(不存在则只用内置规则)构造 Matcher。
func Load(root string) (*Matcher, error) {
	data, err := os.ReadFile(filepath.Join(root, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return New(nil), nil
	}
	if err != nil {
		return nil, fmt.Errorf("ignore: 读取 %s: %w", FileName, err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ignore: 解析 %s: %w", FileName, err)
	}
	return New(lines), nil
}

// compile 把一行规则编译成正则;空行与注释返回 ok=false。
func compile(line string) (rule, bool) {
	p := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if p == "" || strings.HasPrefix(p, "#") {
		return rule{}, false
	}
	var r rule
	if strings.HasSuffix(p, "/") {
		r.dirOnly = true
		p = strings.TrimRight(p, "/")
		if p == "" {
			return rule{}, false
		}
	}
	if strings.Contains(p, "/") {
		p = strings.TrimPrefix(p, "/")
	} else {
		r.basename = true
	}
	r.re = regexp.MustCompile("^" + globToRegexp(p) + "$")
	return r, true
}

// globToRegexp 把 * ? ** 通配转成正则,其余字符一律按字面转义,所以编译不会失败。
func globToRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?") // 零个或多个目录
			i += 3
		case strings.HasPrefix(p[i:], "/**") && i+3 == len(p):
			b.WriteString("(?:/.*)?") // 该目录本身及其下所有内容
			i += 3
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i += 2
		case p[i] == '*':
			b.WriteString("[^/]*")
			i++
		case p[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			// 按完整 UTF-8 字符转义,避免把多字节字符拆开。
			j := i + 1
			for j < len(p) && p[j]&0xC0 == 0x80 {
				j++
			}
			b.WriteString(regexp.QuoteMeta(p[i:j]))
			i = j
		}
	}
	return b.String()
}

// Match 判断库内相对路径 rel('/' 分隔)是否被忽略;isDir 表示 rel 本身是目录。
// 任一祖先目录被忽略时 rel 也被忽略。
func (m *Matcher) Match(rel string, isDir bool) bool {
	segs := strings.Split(rel, "/")
	for i := range segs {
		prefix := strings.Join(segs[:i+1], "/")
		last := i == len(segs)-1
		dir := !last || isDir
		if m.matchOne(prefix, segs[i], dir) {
			return true
		}
	}
	return false
}

func (m *Matcher) matchOne(path, name string, isDir bool) bool {
	for _, r := range m.rules {
		if r.dirOnly && !isDir {
			continue
		}
		target := path
		if r.basename {
			target = name
		}
		if r.re.MatchString(target) {
			return true
		}
	}
	return false
}
