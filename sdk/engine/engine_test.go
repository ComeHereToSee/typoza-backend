package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/ignore"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/fakeserver"
)

// harness 是一个账号 + 一个库;每个 device 是一台独立设备(各自的根目录、状态目录与令牌)。
// 为了让测试不跑 Argon2,这里直接用 api 注册登录,密钥在本地生成后两台设备共享。
type harness struct {
	t       *testing.T
	fs      *fakeserver.Server
	url     string
	keys    *crypto.Keys
	authKey []byte
	vaultID string
}

const testEmail = "engine@example.com"

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fs := fakeserver.New()
	srv := httptest.NewServer(fs.Handler())
	t.Cleanup(func() {
		fs.Close()
		srv.Close()
	})
	h := &harness{t: t, fs: fs, url: srv.URL, keys: crypto.DeriveKeys(crypto.NewAccountKey()), authKey: randBytes(32)}
	c, err := api.New(api.Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Register(context.Background(), api.RegisterRequest{
		Email:                       testEmail,
		KDF:                         api.KDF{Algorithm: "argon2id", MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: randBytes(16)},
		AuthKey:                     h.authKey,
		EncryptedAccountKey:         []byte{1},
		RecoveryAuthKey:             randBytes(32),
		RecoveryEncryptedAccountKey: []byte{1},
		Device:                      api.Device{Name: "setup", Platform: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := CreateVault(context.Background(), c, h.keys, "测试库")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ListVaults(context.Background(), c, h.keys)
	if err != nil || len(vs) != 1 || vs[0].Name != "测试库" || vs[0].ID != v.ID {
		t.Fatalf("ListVaults: %+v %v", vs, err)
	}
	h.vaultID = v.ID
	return h
}

type device struct {
	t      *testing.T
	name   string
	root   string
	trashD string
	client *api.Client
	eng    *Engine

	mu      sync.Mutex
	trashed []string
	events  []Event
}

// mtimeTick 给所有设备写入的文件分配互不相同的 mtime。
var mtimeTick atomic.Int64

func (h *harness) device(name string) *device {
	t := h.t
	t.Helper()
	c, err := api.New(api.Options{BaseURL: h.url})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), api.LoginRequest{
		Email: testEmail, AuthKey: h.authKey, Device: api.Device{Name: name, Platform: "test"},
	}); err != nil {
		t.Fatal(err)
	}
	d := &device{t: t, name: name, root: t.TempDir(), trashD: t.TempDir(), client: c}
	eng, err := New(Options{
		Root: d.root, StateDir: t.TempDir(), VaultID: h.vaultID, Keys: h.keys, Client: c,
		DeviceName: name, Trash: d.trash, OnEvent: d.onEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	d.eng = eng
	return d
}

// trash 模拟宿主把文件移进废纸篓。
func (d *device) trash(abs string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rel, err := filepath.Rel(d.root, abs)
	if err != nil {
		return err
	}
	dst := filepath.Join(d.trashD, fmt.Sprintf("%d-%s", len(d.trashed), filepath.Base(abs)))
	if err := os.Rename(abs, dst); err != nil {
		return err
	}
	d.trashed = append(d.trashed, filepath.ToSlash(rel))
	return nil
}

func (d *device) onEvent(ev Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, ev)
}

func (d *device) eventsOf(kind EventKind) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Event
	for _, ev := range d.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

func (d *device) trashedPaths() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.trashed...)
}

// write 写文件并显式设置一个递增的 mtime:某些文件系统的时间戳粒度较粗,
// 同一毫秒内写两次同样长度的内容会被当成没变。
func (d *device) write(rel string, data []byte) {
	d.t.Helper()
	abs := filepath.Join(d.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		d.t.Fatal(err)
	}
	mt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(mtimeTick.Add(1)) * time.Second)
	if err := os.Chtimes(abs, mt, mt); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) writeStr(rel, s string) { d.write(rel, []byte(s)) }

func (d *device) read(rel string) string {
	d.t.Helper()
	data, err := os.ReadFile(filepath.Join(d.root, filepath.FromSlash(rel)))
	if err != nil {
		d.t.Fatalf("%s 读取 %s: %v", d.name, rel, err)
	}
	return string(data)
}

func (d *device) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(d.root, filepath.FromSlash(rel)))
	return err == nil
}

func (d *device) remove(rel string) {
	d.t.Helper()
	if err := os.Remove(filepath.Join(d.root, filepath.FromSlash(rel))); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) sync() {
	d.t.Helper()
	if err := d.eng.SyncNow(context.Background()); err != nil {
		d.t.Fatalf("%s 同步失败: %v", d.name, err)
	}
}

// files 返回库内全部普通文件(不含被忽略的临时文件),路径 → 内容。
func (d *device) files() map[string]string {
	d.t.Helper()
	out := make(map[string]string)
	err := filepath.WalkDir(d.root, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() || !de.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(d.root, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func assertSameFiles(t *testing.T, a, b *device) {
	t.Helper()
	fa, fb := a.files(), b.files()
	if strings.Join(sortedKeys(fa), "\n") != strings.Join(sortedKeys(fb), "\n") {
		t.Fatalf("两台设备文件列表不同:\n%s: %v\n%s: %v", a.name, sortedKeys(fa), b.name, sortedKeys(fb))
	}
	for k, v := range fa {
		if fb[k] != v {
			t.Fatalf("%s 内容不同:\n%s: %q\n%s: %q", k, a.name, v, b.name, fb[k])
		}
	}
}

var conflictRe = regexp.MustCompile(`^(.*) \(冲突副本 (.+) \d{4}-\d{2}-\d{2} \d{4}( \d+)?\)(\.[^.]*)?$`)

func conflictCopies(files map[string]string) []string {
	var out []string
	for p := range files {
		if conflictRe.MatchString(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func TestUploadPullModify(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("笔记/周报.md", "# 周报\n第一周\n")
	a.writeStr("empty.txt", "")
	a.write("bin/data.bin", randBytes(1000))
	a.sync()
	b.sync()
	assertSameFiles(t, a, b)

	// 远端 mtime 原样落到本地(毫秒精度)。
	fa, _ := os.Stat(filepath.Join(a.root, "笔记", "周报.md"))
	fb, _ := os.Stat(filepath.Join(b.root, "笔记", "周报.md"))
	if fa.ModTime().UnixMilli() != fb.ModTime().UnixMilli() {
		t.Fatalf("mtime 未保留: %v vs %v", fa.ModTime(), fb.ModTime())
	}

	b.writeStr("笔记/周报.md", "# 周报\n第一周\n第二周\n")
	b.sync()
	a.sync()
	if got := a.read("笔记/周报.md"); got != "# 周报\n第一周\n第二周\n" {
		t.Fatalf("A 未收到 B 的修改: %q", got)
	}
	if n := len(a.eventsOf(EventConflict)) + len(b.eventsOf(EventConflict)); n != 0 {
		t.Fatalf("不应有冲突事件: %d", n)
	}
	// 再同步一次不应产生任何上传。
	before := h.fs.Stats().Commits
	a.sync()
	b.sync()
	if h.fs.Stats().Commits != before {
		t.Fatal("无变化时不应提交")
	}
	if st := a.eng.Status(); st.Syncing || st.LastError != nil || st.LastSuccessAt.IsZero() {
		t.Fatalf("状态不对: %+v", st)
	}
}

const mergeBase = "1\n2\n3\n4\n5\n6\n7\n"

func TestConcurrentEdit_AutoMerge(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("doc.md", mergeBase)
	a.sync()
	b.sync()

	a.writeStr("doc.md", "1 A改\n2\n3\n4\n5\n6\n7\n")
	b.writeStr("doc.md", "1\n2\n3\n4\n5\n6\n7 B改\n")
	a.sync()
	b.sync() // B 拉到 A 的版本,与本地修改三方合并后提交
	a.sync()
	want := "1 A改\n2\n3\n4\n5\n6\n7 B改\n"
	if a.read("doc.md") != want || b.read("doc.md") != want {
		t.Fatalf("合并结果不对:\nA=%q\nB=%q", a.read("doc.md"), b.read("doc.md"))
	}
	if cs := conflictCopies(b.files()); len(cs) != 0 {
		t.Fatalf("自动合并不应产生冲突副本: %v", cs)
	}
	evs := b.eventsOf(EventConflict)
	if len(evs) != 1 || evs[0].ConflictPath != "" || !strings.Contains(evs[0].Reason, "合并") {
		t.Fatalf("B 应报告一次自动合并: %+v", evs)
	}
	assertSameFiles(t, a, b)
}

func TestConcurrentEdit_ConflictCopy(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("doc.md", mergeBase)
	a.sync()
	b.sync()

	a.writeStr("doc.md", "1\n2\n3 A\n4\n5\n6\n7\n")
	b.writeStr("doc.md", "1\n2\n3 B\n4\n5\n6\n7\n")
	a.sync()
	b.sync()
	a.sync()
	assertSameFiles(t, a, b)
	files := b.files()
	if files["doc.md"] != "1\n2\n3 A\n4\n5\n6\n7\n" {
		t.Fatalf("原路径应是先提交的远端版本: %q", files["doc.md"])
	}
	cs := conflictCopies(files)
	if len(cs) != 1 || files[cs[0]] != "1\n2\n3 B\n4\n5\n6\n7\n" {
		t.Fatalf("应有一个保存 B 内容的冲突副本: %v", cs)
	}
	if m := conflictRe.FindStringSubmatch(cs[0]); m[1] != "doc" || m[2] != "设备B" || m[4] != ".md" {
		t.Fatalf("冲突副本命名不对: %s", cs[0])
	}
	evs := b.eventsOf(EventConflict)
	if len(evs) != 1 || evs[0].ConflictPath != cs[0] {
		t.Fatalf("冲突事件不对: %+v", evs)
	}
}

func TestBinaryConflict(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	orig := randBytes(5000)
	a.write("img.png", orig)
	a.sync()
	b.sync()
	va, vb := randBytes(5000), randBytes(6000)
	a.write("img.png", va)
	b.write("img.png", vb)
	a.sync()
	b.sync()
	a.sync()
	assertSameFiles(t, a, b)
	files := a.files()
	if files["img.png"] != string(va) {
		t.Fatal("原路径应是 A 的版本")
	}
	cs := conflictCopies(files)
	if len(cs) != 1 || files[cs[0]] != string(vb) || !strings.HasSuffix(cs[0], ".png") {
		t.Fatalf("二进制冲突应生成 B 内容的冲突副本: %v", cs)
	}
}

func TestRemoteDelete_TrashHookAndRestore(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("a.md", "要删的文件\n")
	a.writeStr("keep.md", "保留\n")
	a.sync()
	b.sync()

	a.remove("a.md")
	a.sync()
	b.sync()
	if got := b.trashedPaths(); len(got) != 1 || got[0] != "a.md" {
		t.Fatalf("B 应通过 Trash 钩子移走 a.md: %v", got)
	}
	if b.exists("a.md") || !b.exists("keep.md") {
		t.Fatal("B 的文件状态不对")
	}

	items, err := b.eng.Trash(context.Background())
	if err != nil || len(items) != 1 || items[0].Path != "a.md" {
		t.Fatalf("回收站应列出 a.md: %+v %v", items, err)
	}
	if err := b.eng.RestoreFromTrash(context.Background(), items[0].FileID); err != nil {
		t.Fatal(err)
	}
	if b.read("a.md") != "要删的文件\n" {
		t.Fatal("B 恢复后应立即落盘")
	}
	a.sync()
	if a.read("a.md") != "要删的文件\n" {
		t.Fatal("A 应收到恢复的文件")
	}
	if items, _ := a.eng.Trash(context.Background()); len(items) != 0 {
		t.Fatalf("恢复后回收站应为空: %+v", items)
	}

	// 永久删除:只能作用于回收站里的文件。
	a.remove("a.md")
	a.sync()
	items, _ = a.eng.Trash(context.Background())
	if len(items) != 1 {
		t.Fatalf("应有 1 个回收站文件: %+v", items)
	}
	if err := a.eng.Purge(context.Background(), items[0].FileID); err != nil {
		t.Fatal(err)
	}
	if items, _ := a.eng.Trash(context.Background()); len(items) != 0 {
		t.Fatal("永久删除后回收站应为空")
	}
}

func TestLocalDeleteVsRemoteModify_KeepsContent(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("x.md", "v1\n")
	a.sync()
	b.sync()
	a.remove("x.md")
	b.writeStr("x.md", "v2 B 改了\n")
	b.sync()
	a.sync()
	if a.read("x.md") != "v2 B 改了\n" {
		t.Fatal("远端修改应优先于本地删除")
	}
	if len(b.trashedPaths()) != 0 {
		t.Fatal("不应把 B 的文件移进废纸篓")
	}
}

func TestRemoteDeleteVsLocalModify_KeepsContent(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("x.md", "v1\n")
	a.sync()
	b.sync()
	a.remove("x.md")
	a.sync()
	b.writeStr("x.md", "B 离线时改的\n")
	b.sync()
	if len(b.trashedPaths()) != 0 || b.read("x.md") != "B 离线时改的\n" {
		t.Fatal("本地有修改时不应移进废纸篓")
	}
	a.sync()
	if a.read("x.md") != "B 离线时改的\n" {
		t.Fatal("A 应收到 B 复活的文件")
	}
}

func TestRename_ReusesChunks(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	content := randBytes(200 * 1024)
	a.write("old/name.bin", content)
	a.sync()
	b.sync()
	puts := h.fs.Stats().ChunkPuts

	if err := os.MkdirAll(filepath.Join(a.root, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(a.root, "old", "name.bin"), filepath.Join(a.root, "new", "名字.bin")); err != nil {
		t.Fatal(err)
	}
	a.sync()
	if got := h.fs.Stats().ChunkPuts; got != puts {
		t.Fatalf("改名不应重传块: PUT %d → %d", puts, got)
	}
	synced := a.eventsOf(EventSynced)
	found := false
	for _, ev := range synced {
		if ev.Path == "new/名字.bin" && strings.Contains(ev.Reason, "改名") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应识别为改名: %+v", synced)
	}
	b.sync()
	if b.exists("old/name.bin") || b.read("new/名字.bin") != string(content) {
		t.Fatal("B 应完成改名")
	}
}

func TestLargeFileAndDedup(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	big := randBytes(2*crypto.ChunkSize + 12345) // 3 块
	a.write("big.bin", big)
	a.write("big-copy.bin", big)                              // 同内容:块全部去重
	a.write("zeros.bin", make([]byte, 2*crypto.ChunkSize+10)) // 文件内两块相同
	a.write("small.txt", bytes.Repeat([]byte("压缩友好 "), 1000)) // 可压缩
	a.sync()
	// big 3 块 + zeros 2 种块 + small 1 块 = 6 个不同的块。
	if got := h.fs.Stats().ChunkPuts; got != 6 {
		t.Fatalf("块应只上传一次: PUT=%d,预期 6", got)
	}
	b.sync()
	assertSameFiles(t, a, b)
}

func TestTamperedChunkIsRejected(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("secret.md", "机密内容\n")
	a.sync()
	ids := h.fs.ChunkIDs()
	if len(ids) != 1 || !h.fs.TamperChunk(ids[0]) {
		t.Fatalf("准备篡改失败: %v", ids)
	}
	err := b.eng.SyncNow(context.Background())
	if err == nil || !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("篡改的块必须报错: %v", err)
	}
	if b.exists("secret.md") {
		t.Fatal("校验失败的内容不能落盘")
	}
	if c, _ := b.eng.store.cursor(); c != 0 {
		t.Fatalf("有文件失败时不应推进游标: %d", c)
	}
}

func TestSamePathCreatedOnTwoDevices(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("same.md", "A 的内容\n")
	b.writeStr("same.md", "B 的内容\n")
	a.writeStr("dup.md", "一样的内容\n")
	b.writeStr("dup.md", "一样的内容\n")
	a.sync()
	b.sync()
	a.sync()
	b.sync()
	assertSameFiles(t, a, b)
	files := a.files()
	if files["dup.md"] != "一样的内容\n" {
		t.Fatal("同内容文件应保留")
	}
	cs := conflictCopies(files)
	if len(cs) != 1 {
		t.Fatalf("应只有 same.md 一个冲突副本: %v", cs)
	}
	got := []string{files["same.md"], files[cs[0]]}
	sort.Strings(got)
	if got[0] != "A 的内容\n" || got[1] != "B 的内容\n" {
		t.Fatalf("两方内容都必须保留: %q", got)
	}
	// 再同步一轮应稳定,不再产生提交。
	before := h.fs.Stats().Commits
	a.sync()
	b.sync()
	if h.fs.Stats().Commits != before {
		t.Fatal("收敛后不应再提交")
	}
}

// pushOnly 只扫描并推送、不先拉取,模拟两台设备几乎同时提交(彼此都还没看到对方)。
func (d *device) pushOnly() {
	d.t.Helper()
	d.eng.syncMu.Lock()
	defer d.eng.syncMu.Unlock()
	d.eng.ign = ignore.New(nil)
	again, errs, err := d.eng.push(context.Background())
	if err != nil || len(errs) != 0 || again {
		d.t.Fatalf("%s 推送失败: again=%v errs=%v err=%v", d.name, again, errs, err)
	}
}

func TestPathClashBetweenCommittedFiles(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("same.md", "A 的内容\n")
	b.writeStr("same.md", "B 的内容\n")
	a.writeStr("dup.md", "一样的内容\n")
	b.writeStr("dup.md", "一样的内容\n")
	a.sync()
	b.pushOnly() // 服务器上 same.md、dup.md 各有两个 fileId
	b.sync()
	a.sync()
	b.sync()
	assertSameFiles(t, a, b)
	files := a.files()
	if files["dup.md"] != "一样的内容\n" {
		t.Fatal("同内容文件应保留")
	}
	cs := conflictCopies(files)
	if len(cs) != 1 {
		t.Fatalf("应只有 same.md 一个冲突副本: %v", cs)
	}
	got := []string{files["same.md"], files[cs[0]]}
	sort.Strings(got)
	if got[0] != "A 的内容\n" || got[1] != "B 的内容\n" {
		t.Fatalf("两方内容都必须保留: %q", got)
	}
	// 每个路径在服务器上只剩一个存活的 fileId。
	recs, err := a.eng.store.all()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.FileID] = true
	}
	if len(ids) != len(recs) {
		t.Fatalf("同一 fileId 不应对应多个路径: %d 个记录 %d 个 fileId", len(recs), len(ids))
	}
	before := h.fs.Stats().Commits
	a.sync()
	b.sync()
	if h.fs.Stats().Commits != before {
		t.Fatal("收敛后不应再提交")
	}
}

func TestHistoryRestore(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	for i := 1; i <= 3; i++ {
		a.writeStr("h.md", fmt.Sprintf("第 %d 版\n", i))
		a.sync()
	}
	vs, err := a.eng.Versions(context.Background(), "h.md")
	if err != nil || len(vs) != 3 || vs[0].Version != 3 || vs[2].Version != 1 || vs[2].Path != "h.md" {
		t.Fatalf("历史版本不对: %+v %v", vs, err)
	}
	if err := a.eng.Restore(context.Background(), "h.md", 1); err != nil {
		t.Fatal(err)
	}
	if a.read("h.md") != "第 1 版\n" {
		t.Fatalf("恢复后本地内容不对: %q", a.read("h.md"))
	}
	b.sync()
	if b.read("h.md") != "第 1 版\n" {
		t.Fatal("B 应收到恢复后的版本")
	}
	vs, _ = a.eng.Versions(context.Background(), "h.md")
	if len(vs) != 4 || vs[0].ContentHash != vs[3].ContentHash {
		t.Fatalf("恢复应产生新版本且内容等于版本 1: %+v", vs)
	}
	if _, err := a.eng.Versions(context.Background(), "nope.md"); !errors.Is(err, ErrNotTracked) {
		t.Fatalf("未同步路径应返回 ErrNotTracked: %v", err)
	}
}

func TestIgnoreRules(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr(".typozaignore", "# 本库规则\n*.log\nbuild/\n")
	a.writeStr("note.md", "x\n")
	a.writeStr(".DS_Store", "x")
	a.writeStr("sub/.DS_Store", "x")
	a.writeStr("a.tmp", "x")
	a.writeStr("~$doc.docx", "x")
	a.writeStr("debug.log", "x")
	a.writeStr("build/out.txt", "x")
	a.writeStr(".git/config", "x")
	a.sync()
	b.sync()
	got := sortedKeys(b.files())
	want := []string{".typozaignore", "note.md"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("B 收到的文件 = %v,预期 %v", got, want)
	}
}

func TestTokenExpiryDuringSync(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	a.writeStr("t.md", "x\n")
	h.fs.ExpireAccessTokens()
	a.sync()
	b.sync()
	if b.read("t.md") != "x\n" {
		t.Fatal("令牌过期后应自动刷新并完成同步")
	}
	if h.fs.Stats().Refreshes < 2 {
		t.Fatalf("两台设备都应刷新令牌: %d", h.fs.Stats().Refreshes)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	h := newHarness(t)
	c, _ := api.New(api.Options{BaseURL: h.url})
	root := t.TempDir()
	base := Options{Root: root, StateDir: filepath.Join(root, ".typoza", "state"), VaultID: h.vaultID, Keys: h.keys,
		Client: c, DeviceName: "d", Trash: func(string) error { return nil }}
	e, err := New(base)
	if err != nil {
		t.Fatalf("状态目录在 .typoza 下应允许: %v", err)
	}
	_ = e.Close()
	bad := []func(o *Options){
		func(o *Options) { o.StateDir = filepath.Join(root, "state") },
		func(o *Options) { o.StateDir = root },
		func(o *Options) { o.Trash = nil },
		func(o *Options) { o.VaultID = "x" },
		func(o *Options) { o.Root = "relative" },
		func(o *Options) { o.DeviceName = " " },
	}
	for i, f := range bad {
		o := base
		f(&o)
		if e, err := New(o); err == nil {
			_ = e.Close()
			t.Errorf("case %d 应报错", i)
		}
	}
}

// TestStart_WatcherAndPush 验证后台模式:A 的本地修改经去抖上传,B 经服务器推送立即拉取。
func TestStart_WatcherAndPush(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("设备A"), h.device("设备B")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.eng.Start(ctx); err == nil {
		t.Fatal("重复 Start 应报错")
	}
	// 新建子目录里的文件也要被监听到(fsnotify 不递归,需补加监听)。
	time.Sleep(200 * time.Millisecond)
	if err := os.MkdirAll(filepath.Join(a.root, "新目录"), 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(a.root, "新目录", "live.md"), []byte("实时\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if data, err := os.ReadFile(filepath.Join(b.root, "新目录", "live.md")); err == nil && string(data) == "实时\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B 未在时限内收到文件;A 事件: %+v", a.eventsOf(EventError))
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := a.eng.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.eng.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConflictName(t *testing.T) {
	h := newHarness(t)
	a := h.device("Z 的/Mac")
	a.eng.now = func() time.Time { return time.Date(2026, 10, 16, 9, 5, 0, 0, time.Local) }
	cases := map[string]*regexp.Regexp{
		"a/周报.md":       regexp.MustCompile(`^a/周报 \(冲突副本 Z 的-Mac \d{4}-\d{2}-\d{2} \d{4}\)\.md$`),
		"README":        regexp.MustCompile(`^README \(冲突副本 Z 的-Mac \d{4}-\d{2}-\d{2} \d{4}\)$`),
		".typozaignore": regexp.MustCompile(`^\.typozaignore \(冲突副本 Z 的-Mac \d{4}-\d{2}-\d{2} \d{4}\)$`),
		"x.tar.gz":      regexp.MustCompile(`^x\.tar \(冲突副本 Z 的-Mac \d{4}-\d{2}-\d{2} \d{4}\)\.gz$`),
	}
	for in, re := range cases {
		got, err := a.eng.conflictName(in)
		if err != nil || !re.MatchString(got) {
			t.Errorf("conflictName(%q) = %q, %v", in, got, err)
		}
	}
	// 已存在时追加序号。
	first, _ := a.eng.conflictName("n.md")
	a.writeStr(first, "x")
	second, _ := a.eng.conflictName("n.md")
	if first != "n (冲突副本 Z 的-Mac 2026-10-16 0905).md" || second != "n (冲突副本 Z 的-Mac 2026-10-16 0905 2).md" {
		t.Fatalf("重名时应追加序号: %q → %q", first, second)
	}
}
