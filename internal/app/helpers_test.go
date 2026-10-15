package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ComeHereToSee/typoza-backend/internal/app"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/testutil"
)

// env 是一个独立的服务实例(独立 schema、独立对象存储)加一个 HTTP 测试服务器。
type env struct {
	t   *testing.T
	cfg config.Config
	app *app.App
	srv *httptest.Server
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	cfg := testutil.NewTestConfig(t)
	if mutate != nil {
		mutate(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := app.New(t.Context(), cfg, log)
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
	return &env{t: t, cfg: cfg, app: a, srv: srv}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do 发请求;body 为 []byte 时按原样作为二进制体,否则编码为 JSON。
func (e *env) do(method, path, token string, body any) response {
	e.t.Helper()
	var rd io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
		contentType = "application/octet-stream"
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
		contentType = "application/json"
	}
	req, err := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return response{status: res.StatusCode, header: res.Header, body: raw}
}

// call 发请求、断言状态码,并把响应体解码到 out(可为 nil)。
func (e *env) call(method, path, token string, body any, wantStatus int, out any) response {
	e.t.Helper()
	r := e.do(method, path, token, body)
	if r.status != wantStatus {
		e.t.Fatalf("%s %s: 状态码 %d,期望 %d;响应 %s", method, path, r.status, wantStatus, r.body)
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			e.t.Fatalf("%s %s: 解析响应: %v (%s)", method, path, err, r.body)
		}
	}
	return r
}

// apiError 解析协议错误体。
type apiError struct {
	Error struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Missing []string        `json:"missing"`
		Head    json.RawMessage `json:"head"`
	} `json:"error"`
}

// expectError 断言状态码与错误码,返回解析后的错误体。
func (e *env) expectError(method, path, token string, body any, wantStatus int, wantCode string) apiError {
	e.t.Helper()
	var ae apiError
	e.call(method, path, token, body, wantStatus, &ae)
	if ae.Error.Code != wantCode || ae.Error.Message == "" {
		e.t.Fatalf("%s %s: 错误码 %q,期望 %q", method, path, ae.Error.Code, wantCode)
	}
	return ae
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newChunkID(t *testing.T) string { return hex.EncodeToString(randBytes(t, 32)) }

func uniqueEmail(t *testing.T) string {
	return "u" + hex.EncodeToString(randBytes(t, 6)) + "@example.com"
}

type kdf struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   int64  `json:"memoryKiB"`
	Iterations  int64  `json:"iterations"`
	Parallelism int64  `json:"parallelism"`
	Salt        string `json:"salt"`
}

func newKDF(t *testing.T) kdf {
	return kdf{Algorithm: "argon2id", MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: b64(randBytes(t, 16))}
}

type session struct {
	UserID               string `json:"userId"`
	DeviceID             string `json:"deviceId"`
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int    `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
	EncryptedAccountKey  string `json:"encryptedAccountKey"`
	KDF                  kdf    `json:"kdf"`
}

type tokens struct {
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int    `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
}

// user 模拟一个客户端账号:服务端只看得到这些派生值与密文。
type user struct {
	email       string
	authKey     []byte
	recoveryKey []byte
	kdf         kdf
	wrapped     string // encryptedAccountKey
	session     session
}

func device(name string) map[string]string {
	return map[string]string{"name": name, "platform": "macos"}
}

func (e *env) register(email string) *user {
	e.t.Helper()
	u := &user{
		email:       email,
		authKey:     randBytes(e.t, 32),
		recoveryKey: randBytes(e.t, 32),
		kdf:         newKDF(e.t),
		wrapped:     b64(randBytes(e.t, 61)),
	}
	e.call(http.MethodPost, "/v1/auth/register", "", map[string]any{
		"email":                       email,
		"kdf":                         u.kdf,
		"authKey":                     b64(u.authKey),
		"encryptedAccountKey":         u.wrapped,
		"recoveryAuthKey":             b64(u.recoveryKey),
		"recoveryEncryptedAccountKey": b64(randBytes(e.t, 61)),
		"device":                      device("设备 A"),
	}, http.StatusCreated, &u.session)
	return u
}

func (e *env) login(u *user, deviceName string, extra map[string]any) session {
	e.t.Helper()
	body := map[string]any{"email": u.email, "authKey": b64(u.authKey), "device": device(deviceName)}
	for k, v := range extra {
		body[k] = v
	}
	var s session
	e.call(http.MethodPost, "/v1/auth/login", "", body, http.StatusOK, &s)
	return s
}

func (e *env) refresh(refreshToken string) response {
	e.t.Helper()
	return e.do(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": refreshToken})
}

func (e *env) createVault(token string) string {
	e.t.Helper()
	id := newUUID(e.t)
	e.call(http.MethodPost, "/v1/vaults", token, map[string]string{"id": id, "encryptedName": b64(randBytes(e.t, 40))}, http.StatusCreated, nil)
	return id
}

func (e *env) putChunk(token, id string, data []byte, wantStatus int) {
	e.t.Helper()
	e.call(http.MethodPut, "/v1/chunks/"+id, token, data, wantStatus, nil)
}

type commitResult struct {
	Version int64 `json:"version"`
	Seq     int64 `json:"seq"`
}

func commitBody(base int64, chunks []string, size int64, deleted bool, manifest []byte) map[string]any {
	if chunks == nil {
		chunks = []string{}
	}
	return map[string]any{"baseVersion": base, "manifest": b64(manifest), "chunks": chunks, "size": size, "deleted": deleted}
}

func (e *env) commit(token, vaultID, fileID string, base int64, chunks []string, size int64, deleted bool) commitResult {
	e.t.Helper()
	var res commitResult
	e.call(http.MethodPost, "/v1/vaults/"+vaultID+"/files/"+fileID+"/commit", token,
		commitBody(base, chunks, size, deleted, randBytes(e.t, 48)), http.StatusOK, &res)
	return res
}

type version struct {
	FileID    string `json:"fileId"`
	Version   int64  `json:"version"`
	Seq       int64  `json:"seq"`
	Manifest  string `json:"manifest"`
	Deleted   bool   `json:"deleted"`
	Size      int64  `json:"size"`
	DeviceID  string `json:"deviceId"`
	CreatedAt string `json:"createdAt"`
}

type changesPage struct {
	Changes []version `json:"changes"`
	Cursor  int64     `json:"cursor"`
	HasMore bool      `json:"hasMore"`
}

func newUUID(t *testing.T) string {
	b := randBytes(t, 16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

// exec 在被测实例的 schema 里直接执行 SQL(用于把时间拨回过去等测试准备)。
func (e *env) exec(sql string, args ...any) int64 {
	e.t.Helper()
	tag, err := e.app.Pool().Exec(context.Background(), sql, args...)
	if err != nil {
		e.t.Fatalf("执行 SQL 失败: %v\n%s", err, sql)
	}
	return tag.RowsAffected()
}

func (e *env) queryInt(sql string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.app.Pool().QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("查询失败: %v\n%s", err, sql)
	}
	return n
}

func decodeInto(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("解析响应: %v (%s)", err, raw)
	}
}
