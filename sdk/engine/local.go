package engine

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/relpath"
)

// errLocalChanged 表示本地文件在同步过程中被改动;当前操作放弃,下一轮按新状态处理。
var errLocalChanged = errors.New("engine: 本地文件在同步过程中被修改")

// tmpPattern 是引擎写入临时文件的名字模式:以点开头、以 .tmp 结尾,被内置忽略规则覆盖。
const tmpPattern = ".typoza-*.tmp"

const baseDirName = "base"

// fileStat 是本地文件的关键属性。
type fileStat struct {
	exists  bool
	regular bool
	size    int64
	mtime   int64 // UnixNano
}

func statOf(fi fs.FileInfo) fileStat {
	return fileStat{exists: true, regular: fi.Mode().IsRegular(), size: fi.Size(), mtime: fi.ModTime().UnixNano()}
}

// statFile 用 Lstat 取属性(不跟随符号链接);不存在时 exists=false 且不报错。
func statFile(abs string) (fileStat, error) {
	fi, err := os.Lstat(abs)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return fileStat{}, nil
	}
	if err != nil {
		return fileStat{}, fmt.Errorf("engine: 读取 %s 的属性: %w", abs, err)
	}
	return statOf(fi), nil
}

func (r *fileRecord) matches(st fileStat) bool {
	return st.exists && st.regular && st.size == r.Size && st.mtime == r.MTime
}

// localInfo 是本地文件的当前状态。
type localInfo struct {
	st   fileStat
	hash string // 文件存在时的内容摘要
}

// inspect 取本地文件状态。有记录且 mtime/size 都没变时直接沿用记录里的摘要(协议 §7.2),否则读文件重算。
// 路径被目录、符号链接等非普通文件占用时返回错误,调用方跳过该文件。
func (e *Engine) inspect(abs string, rec *fileRecord) (localInfo, error) {
	st, err := statFile(abs)
	if err != nil {
		return localInfo{}, err
	}
	if !st.exists {
		return localInfo{st: st}, nil
	}
	if !st.regular {
		return localInfo{}, fmt.Errorf("engine: %s 被非普通文件(目录或符号链接)占用", abs)
	}
	if rec != nil && !rec.NeedsCommit && rec.matches(st) {
		return localInfo{st: st, hash: rec.ContentHash}, nil
	}
	hash, st2, err := e.hashFile(abs)
	if err != nil {
		return localInfo{}, err
	}
	return localInfo{st: st2, hash: hash}, nil
}

// hashFile 流式计算文件内容摘要;读的过程中大小变了返回 errLocalChanged。
func (e *Engine) hashFile(abs string) (string, fileStat, error) {
	f, err := os.Open(abs) // #nosec G304 -- 同步文件夹里的文件,路径由引擎在根目录下拼出
	if err != nil {
		return "", fileStat{}, fmt.Errorf("engine: 打开 %s: %w", abs, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fileStat{}, fmt.Errorf("engine: 读取 %s 的属性: %w", abs, err)
	}
	h := crypto.NewContentHasher(e.keys.ChunkID)
	n, err := io.Copy(h, f)
	if err != nil {
		return "", fileStat{}, fmt.Errorf("engine: 读取 %s: %w", abs, err)
	}
	if n != fi.Size() {
		return "", fileStat{}, errLocalChanged
	}
	return h.Sum(), statOf(fi), nil
}

// readVerified 读出整个文件并确认内容摘要仍是 want(用于合并、复制冲突副本前防止读到中途被改的内容)。
func (e *Engine) readVerified(abs, want string) ([]byte, error) {
	data, err := os.ReadFile(abs) // #nosec G304 -- 同步文件夹里的文件,路径由引擎在根目录下拼出
	if err != nil {
		return nil, fmt.Errorf("engine: 读取 %s: %w", abs, err)
	}
	if crypto.ContentHash(e.keys.ChunkID, data) != want {
		return nil, errLocalChanged
	}
	return data, nil
}

// ensureParent 逐级创建 rel 的父目录。任何一级是符号链接或普通文件都拒绝写入,
// 防止远端路径借本地符号链接写到库目录之外。
func (e *Engine) ensureParent(rel string) error {
	dir := relpath.Dir(rel)
	if dir == "" {
		return nil
	}
	cur := e.root
	for _, seg := range strings.Split(dir, "/") {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { // #nosec G301 -- 用户文档里的普通文件夹,与 Finder 新建的权限一致
				return fmt.Errorf("engine: 创建目录 %s: %w", cur, err)
			}
			fi, err = os.Lstat(cur)
		}
		if err != nil {
			return fmt.Errorf("engine: 读取目录 %s: %w", cur, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("engine: %s 不是目录(或是符号链接),拒绝写入 %q", cur, rel)
		}
	}
	return nil
}

// expect 描述落盘前目标路径应处的状态,不符说明用户刚改过,放弃本次写入。
type expect struct {
	absent bool  // 目标必须不存在
	size   int64 // 否则必须仍是这个大小与 mtime
	mtime  int64
}

func expectAbsent() expect          { return expect{absent: true} }
func expectStat(st fileStat) expect { return expect{size: st.size, mtime: st.mtime} }

func checkExpect(abs string, ex expect) (fileStat, error) {
	st, err := statFile(abs)
	if err != nil {
		return fileStat{}, err
	}
	if ex.absent {
		if st.exists {
			return st, errLocalChanged
		}
		return st, nil
	}
	if !st.exists || !st.regular || st.size != ex.size || st.mtime != ex.mtime {
		return st, errLocalChanged
	}
	return st, nil
}

// place 把同目录下的临时文件原子重命名到 rel;重命名前再核一次目标状态。
// 失败(含 errLocalChanged)时删除临时文件。
func (e *Engine) place(tmp, rel string, ex expect) (fileStat, error) {
	abs := e.abs(rel)
	cur, err := checkExpect(abs, ex)
	if err != nil {
		_ = os.Remove(tmp)
		return fileStat{}, err
	}
	// 覆盖已有文件时沿用其权限,新文件用常规的 0644。
	perm := fs.FileMode(0o644)
	if cur.exists {
		if fi, err := os.Lstat(abs); err == nil {
			perm = fi.Mode().Perm()
		}
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return fileStat{}, fmt.Errorf("engine: 设置 %s 的权限: %w", tmp, err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fileStat{}, fmt.Errorf("engine: 落盘 %s: %w", rel, err)
	}
	st, err := statFile(abs)
	if err != nil {
		return fileStat{}, err
	}
	return st, nil
}

// writeTemp 在 rel 所在目录写一个临时文件并刷盘,返回其路径。
func (e *Engine) writeTemp(rel string, data []byte, mtime time.Time) (string, error) {
	if err := e.ensureParent(rel); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(e.abs(rel)), tmpPattern)
	if err != nil {
		return "", fmt.Errorf("engine: 创建临时文件: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil && !mtime.IsZero() {
		werr = os.Chtimes(tmp, mtime, mtime)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("engine: 写临时文件 %s: %w", tmp, werr)
	}
	return tmp, nil
}

// writeAtomic 原子写入整个文件(先写同目录临时文件,核对目标状态后重命名)。
func (e *Engine) writeAtomic(rel string, data []byte, mtime time.Time, ex expect) (fileStat, error) {
	tmp, err := e.writeTemp(rel, data, mtime)
	if err != nil {
		return fileStat{}, err
	}
	return e.place(tmp, rel, ex)
}

// conflictName 生成冲突副本路径:「原名 (冲突副本 <设备名> <YYYY-MM-DD HHmm>).扩展名」(协议 §7.5)。
// 已被占用(本地有文件或有记录)时追加序号。
func (e *Engine) conflictName(rel string) (string, error) {
	dir, base := relpath.Dir(rel), relpath.Base(rel)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" { // .typozaignore 这类以点开头、没有扩展名的文件
		stem, ext = base, ""
	}
	device := sanitizeName(e.deviceName)
	stamp := e.now().Format("2006-01-02 1504")
	for i := 1; i < 1000; i++ {
		seq := ""
		if i > 1 {
			seq = " " + strconv.Itoa(i)
		}
		name := norm.NFC.String(stem + " (冲突副本 " + device + " " + stamp + seq + ")" + ext)
		cand := name
		if dir != "" {
			cand = dir + "/" + name
		}
		if err := relpath.Validate(cand); err != nil {
			return "", fmt.Errorf("engine: 生成冲突副本名: %w", err)
		}
		st, err := statFile(e.abs(cand))
		if err != nil {
			return "", err
		}
		rec, err := e.store.get(cand)
		if err != nil {
			return "", err
		}
		if !st.exists && rec == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("engine: 无法为 %q 生成不重名的冲突副本", rel)
}

// sanitizeName 去掉设备名里不能出现在文件名中的字符。
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == 0:
			return '-'
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if s == "" {
		return "未知设备"
	}
	return s
}

// ---- 合并基线 ----

func (e *Engine) basePath(hash string) string {
	return filepath.Join(e.stateDir, baseDirName, hash)
}

// saveBase 保存上次同步的文本内容,作为将来三方合并的基线。按内容摘要命名,已存在则跳过。
func (e *Engine) saveBase(hash string, data []byte) error {
	if !crypto.ValidContentHash(hash) {
		return fmt.Errorf("engine: 非法的内容摘要 %q", hash)
	}
	p := e.basePath(hash)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	f, err := os.CreateTemp(filepath.Dir(p), tmpPattern)
	if err != nil {
		return fmt.Errorf("engine: 保存合并基线: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("engine: 保存合并基线: %w", werr)
	}
	return nil
}

// loadBase 读取合并基线;不存在时 ok=false。
func (e *Engine) loadBase(hash string) ([]byte, bool, error) {
	if !crypto.ValidContentHash(hash) {
		return nil, false, nil
	}
	data, err := os.ReadFile(e.basePath(hash)) // #nosec G304 -- 本地状态目录下按已校验的内容摘要取文件
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("engine: 读取合并基线: %w", err)
	}
	if crypto.ContentHash(e.keys.ChunkID, data) != hash {
		// 基线文件损坏就当没有,走冲突副本,不拿错误基线去合并。
		return nil, false, nil
	}
	return data, true, nil
}

// gcBase 删除不再被任何记录引用的基线文件。
func (e *Engine) gcBase() error {
	recs, err := e.store.all()
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(recs))
	for _, r := range recs {
		live[r.ContentHash] = true
	}
	dir := filepath.Join(e.stateDir, baseDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("engine: 读取基线目录: %w", err)
	}
	for _, ent := range entries {
		if !live[ent.Name()] {
			if err := os.Remove(filepath.Join(dir, ent.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("engine: 清理合并基线: %w", err)
			}
		}
	}
	return nil
}
