// Package e2e 用真实服务端(PostgreSQL + 对象存储)与 sdk 同步引擎做端到端测试。
// 每个测试一个独立服务实例(独立 schema、独立桶);两台「设备」是两个 Engine,各用一个临时目录。
// 未设置 TYPOZA_TEST_DATABASE_URL 时整体跳过(见 internal/testutil)。
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ComeHereToSee/typoza-backend/internal/app"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/testutil"
	"github.com/ComeHereToSee/typoza-backend/sdk/account"
	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/engine"
)

// testConfig 复用服务端的隔离测试配置,并关闭限流:
// e2e 在一分钟内从 127.0.0.1 发出大量登录、刷新请求,生产默认的每 IP 30 次/分钟会误伤。
func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := testutil.NewTestConfig(t) // 缺 TYPOZA_TEST_DATABASE_URL 时 t.Skip
	cfg.Limits.IPPerMinute = 0
	cfg.Limits.EmailPerMinute = 0
	cfg.Limits.AccountPerMinute = 0
	return cfg
}

// env 是一个服务实例,外加本测试用到的「明文标记」:测试结束时扫描数据库与对象存储,
// 断言这些标记(文件内容、文件名、库名、主密码、恢复码)一个都不出现。
type env struct {
	t   *testing.T
	cfg config.Config
	app *app.App
	url string

	mu      sync.Mutex
	markers []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := testConfig(t)
	a, err := app.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("app.Close: %v", err)
		}
	})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, cfg: cfg, app: a, url: srv.URL}
	// 在设备(引擎)关闭之后、服务关闭之前执行(Cleanup 后进先出)。
	t.Cleanup(e.assertZeroKnowledge)
	return e
}

// secret 生成一个唯一的明文标记并登记,测试把它放进文件内容或文件名里。
// 用 Base32 文本(含 g-z 字母)而不是十六进制,避免与块 ID、对象键里的十六进制偶然重合。
func (e *env) secret(prefix string) string {
	s := prefix + "-" + rand.Text()
	e.remember(s)
	return s
}

func (e *env) remember(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.markers = append(e.markers, s)
}

// ---- 账号与设备 ----

// countingTransport 统计数据块上传次数,用来断言去重与改名不重传。
type countingTransport struct {
	base http.RoundTripper
	puts *atomic.Int64
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/chunks/") {
		c.puts.Add(1)
	}
	return c.base.RoundTrip(r)
}

type user struct {
	env      *env
	email    string
	password string
	vaultID  string
}

type device struct {
	t       *testing.T
	env     *env
	name    string
	root    string
	trashD  string
	client  *api.Client
	sess    *account.Session
	eng     *engine.Engine
	puts    atomic.Int64
	mu      sync.Mutex
	trashed []string
}

func (e *env) newClient(d *device) *api.Client {
	e.t.Helper()
	var puts *atomic.Int64
	if d != nil {
		puts = &d.puts
	} else {
		puts = new(atomic.Int64)
	}
	c, err := api.New(api.Options{
		BaseURL:    e.url,
		HTTPClient: &http.Client{Timeout: 2 * time.Minute, Transport: countingTransport{base: http.DefaultTransport, puts: puts}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// register 注册账号、创建库,返回第一台设备。
func (e *env) register(deviceName string) (*user, *device, string) {
	e.t.Helper()
	u := &user{env: e, email: strings.ToLower(rand.Text()) + "@e2e.typoza.test", password: e.secret("主密码")}
	d := e.blankDevice(deviceName)
	reg, err := account.Register(context.Background(), d.client, u.email, u.password, api.Device{Name: deviceName, Platform: "macos"})
	if err != nil {
		e.t.Fatalf("注册: %v", err)
	}
	e.remember(reg.RecoveryCode)
	d.sess = &reg.Session
	vaultName := e.secret("库名")
	v, err := engine.CreateVault(context.Background(), d.client, d.sess.Keys, vaultName)
	if err != nil {
		e.t.Fatalf("创建库: %v", err)
	}
	u.vaultID = v.ID
	d.start(u.vaultID)
	return u, d, reg.RecoveryCode
}

// login 用主密码在一台新设备上登录,按库名找到同一个库。
func (u *user) login(deviceName, password string) *device {
	e := u.env
	e.t.Helper()
	d := e.blankDevice(deviceName)
	sess, err := account.Login(context.Background(), d.client, u.email, password, account.LoginOptions{
		Device: api.Device{Name: deviceName, Platform: "macos"},
	})
	if err != nil {
		e.t.Fatalf("%s 登录: %v", deviceName, err)
	}
	d.sess = sess
	vs, err := engine.ListVaults(context.Background(), d.client, sess.Keys)
	if err != nil || len(vs) != 1 || vs[0].ID != u.vaultID {
		e.t.Fatalf("%s 列出库: %+v %v", deviceName, vs, err)
	}
	d.start(u.vaultID)
	return d
}

func (e *env) blankDevice(name string) *device {
	d := &device{t: e.t, env: e, name: name, root: e.t.TempDir(), trashD: e.t.TempDir()}
	d.client = e.newClient(d)
	return d
}

func (d *device) start(vaultID string) {
	d.t.Helper()
	eng, err := engine.New(engine.Options{
		Root: d.root, StateDir: d.t.TempDir(), VaultID: vaultID, Keys: d.sess.Keys, Client: d.client,
		DeviceName: d.name, Trash: d.trash,
	})
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Cleanup(func() { _ = eng.Close() })
	d.eng = eng
}

// trash 模拟宿主把文件移进废纸篓。
func (d *device) trash(abs string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rel, err := filepath.Rel(d.root, abs)
	if err != nil {
		return err
	}
	if err := os.Rename(abs, filepath.Join(d.trashD, fmt.Sprintf("%d-%s", len(d.trashed), filepath.Base(abs)))); err != nil {
		return err
	}
	d.trashed = append(d.trashed, filepath.ToSlash(rel))
	return nil
}

func (d *device) trashedPaths() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.trashed...)
}

// mtimeTick 给写入的文件分配互不相同的 mtime:有的文件系统时间戳粒度较粗,
// 同一时刻写两次同样长度的内容会被当成没变(引擎按协议只看 mtime 与大小)。
var mtimeTick atomic.Int64

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

// files 返回库内全部普通文件:路径 → 内容。
func (d *device) files() map[string]string {
	d.t.Helper()
	out := make(map[string]string)
	err := filepath.WalkDir(d.root, func(p string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || !de.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(d.root, p)
		if err != nil {
			return err
		}
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

func keysOf(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func assertSameFiles(t *testing.T, a, b *device) {
	t.Helper()
	fa, fb := a.files(), b.files()
	if strings.Join(keysOf(fa), "\n") != strings.Join(keysOf(fb), "\n") {
		t.Fatalf("两台设备文件列表不同:\n%s: %v\n%s: %v", a.name, keysOf(fa), b.name, keysOf(fb))
	}
	for k, v := range fa {
		if fb[k] != v {
			t.Fatalf("%s 内容不同(%s vs %s)", k, a.name, b.name)
		}
	}
}

// conflictCopies 找出冲突副本(「原名 (冲突副本 <设备名> <YYYY-MM-DD HHmm>).扩展名」)。
func conflictCopies(files map[string]string) []string {
	var out []string
	for p := range files {
		if strings.Contains(p, " (冲突副本 ") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ---- 零知识断言 ----

// assertZeroKnowledge 扫描本测试 schema 下所有表的所有列、对象存储里所有对象的键与内容,
// 断言不出现任何明文标记(含 base64 / 十六进制解码后的形态)。
func (e *env) assertZeroKnowledge() {
	t := e.t
	e.mu.Lock()
	markers := append([]string(nil), e.markers...)
	e.mu.Unlock()
	if len(markers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool := e.app.Pool()
	rows, err := pool.Query(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Errorf("零知识扫描:列出表: %v", err)
		return
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Errorf("零知识扫描:读表名: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Errorf("零知识扫描:列出表: %v", err)
	}
	if len(tables) == 0 {
		t.Errorf("零知识扫描:没有找到任何表,扫描不成立")
	}
	cells := 0
	for _, tbl := range tables {
		rows, err := pool.Query(ctx, "SELECT * FROM "+pgx.Identifier{tbl}.Sanitize())
		if err != nil {
			t.Errorf("零知识扫描:读表 %s: %v", tbl, err)
			continue
		}
		cols := rows.FieldDescriptions()
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Errorf("零知识扫描:读表 %s: %v", tbl, err)
				break
			}
			for i, v := range vals {
				cells++
				where := fmt.Sprintf("表 %s 列 %s", tbl, cols[i].Name)
				for _, b := range flatten(v) {
					checkMarkers(t, markers, b, where)
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Errorf("零知识扫描:读表 %s: %v", tbl, err)
		}
	}
	if cells == 0 {
		t.Errorf("零知识扫描:数据库里没有任何数据,扫描不成立")
	}

	bs, err := e.blobs()
	if err != nil {
		t.Errorf("零知识扫描:%v", err)
		return
	}
	keys, err := bs.list(ctx)
	if err != nil {
		t.Errorf("零知识扫描:列出对象: %v", err)
	}
	objects := len(keys)
	for _, key := range keys {
		checkMarkers(t, markers, []byte(key), "对象键")
		data, err := bs.get(ctx, key)
		if err != nil {
			t.Errorf("零知识扫描:读对象 %s: %v", key, err)
			continue
		}
		checkMarkers(t, markers, data, "对象 "+key)
	}
	if objects == 0 {
		t.Errorf("零知识扫描:对象存储里没有任何对象,扫描不成立")
	}
}

// blobStore 是测试直接访问对象存储的最小接口(零知识扫描、篡改模拟)。
type blobStore interface {
	list(ctx context.Context) ([]string, error)
	get(ctx context.Context, key string) ([]byte, error)
	put(ctx context.Context, key string, data []byte) error
}

func (e *env) blobs() (blobStore, error) {
	switch e.cfg.Blob.Driver {
	case config.BlobDriverS3:
		mc, err := minio.New(e.cfg.Blob.S3Endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(e.cfg.Blob.S3AccessKey, e.cfg.Blob.S3SecretKey, ""),
			Secure: e.cfg.Blob.S3UseTLS,
			Region: e.cfg.Blob.S3Region,
		})
		if err != nil {
			return nil, fmt.Errorf("S3 客户端: %w", err)
		}
		return s3Blobs{mc: mc, bucket: e.cfg.Blob.S3Bucket}, nil
	case config.BlobDriverFS:
		return fsBlobs{dir: e.cfg.Blob.FSDir}, nil
	default:
		return nil, fmt.Errorf("未知对象存储驱动 %q", e.cfg.Blob.Driver)
	}
}

type s3Blobs struct {
	mc     *minio.Client
	bucket string
}

func (s s3Blobs) list(ctx context.Context) ([]string, error) {
	var keys []string
	for obj := range s.mc.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Recursive: true}) {
		if obj.Err != nil {
			return keys, obj.Err
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

func (s s3Blobs) get(ctx context.Context, key string) ([]byte, error) {
	o, err := s.mc.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer o.Close()
	return io.ReadAll(o)
}

func (s s3Blobs) put(ctx context.Context, key string, data []byte) error {
	_, err := s.mc.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	return err
}

type fsBlobs struct{ dir string }

func (f fsBlobs) list(context.Context) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(f.dir, func(p string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		rel, err := filepath.Rel(f.dir, p)
		if err != nil {
			return err
		}
		keys = append(keys, filepath.ToSlash(rel))
		return nil
	})
	return keys, err
}

func (f fsBlobs) get(_ context.Context, key string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, filepath.FromSlash(key)))
}

func (f fsBlobs) put(_ context.Context, key string, data []byte) error {
	return os.WriteFile(filepath.Join(f.dir, filepath.FromSlash(key)), data, 0o600)
}

// flatten 把 pgx 解出的列值转成字节串;数组逐项展开,其他结构按 JSON 序列化。
func flatten(v any) [][]byte {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return [][]byte{[]byte(x)}
	case []byte:
		return [][]byte{x}
	case []any:
		var out [][]byte
		for _, it := range x {
			out = append(out, flatten(it)...)
		}
		return out
	default:
		b, err := json.Marshal(x)
		if err != nil {
			b = []byte(fmt.Sprint(x))
		}
		return [][]byte{b}
	}
}

// checkMarkers 检查原始字节及其 base64 / 十六进制解码形态里是否出现明文标记。
func checkMarkers(t *testing.T, markers []string, data []byte, where string) {
	t.Helper()
	forms := [][]byte{data}
	s := strings.TrimSpace(string(data))
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if d, err := enc.DecodeString(s); err == nil && len(d) > 0 {
			forms = append(forms, d)
		}
	}
	if h, err := hex.DecodeString(strings.TrimPrefix(s, `\x`)); err == nil && len(h) > 0 {
		forms = append(forms, h)
	}
	for _, m := range markers {
		for _, f := range forms {
			if bytes.Contains(f, []byte(m)) {
				t.Errorf("零知识违规:%s 中出现明文 %q", where, m)
				return
			}
		}
	}
}
