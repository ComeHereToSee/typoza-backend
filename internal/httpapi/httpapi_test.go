package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/metrics"
	"github.com/ComeHereToSee/typoza-backend/internal/ratelimit"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// newTestServer 构造不依赖数据库的 Server:只能覆盖在调用业务层之前就结束的路径。
func newTestServer(t *testing.T, ready func(context.Context) error) (*Server, http.Handler) {
	t.Helper()
	if ready == nil {
		ready = func(context.Context) error { return nil }
	}
	s := &Server{
		metrics:        metrics.New(),
		log:            slog.New(slog.DiscardHandler),
		ready:          ready,
		ipLimiter:      ratelimit.New(30),
		emailLimiter:   ratelimit.New(10),
		accountLimiter: ratelimit.New(1200),
		mux:            http.NewServeMux(),
	}
	s.routes(false)
	return s, s.observe(s.mux)
}

type errorBody struct {
	Error map[string]json.RawMessage `json:"error"`
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) (code, message string, fields map[string]json.RawMessage) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("错误响应 Content-Type 应为 JSON,实际 %q", ct)
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("错误体不是 JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Error == nil {
		t.Fatalf("错误体缺少 error 对象: %s", rec.Body.String())
	}
	if err := json.Unmarshal(body.Error["code"], &code); err != nil {
		t.Fatalf("error.code 缺失: %s", rec.Body.String())
	}
	if err := json.Unmarshal(body.Error["message"], &message); err != nil || message == "" {
		t.Fatalf("error.message 缺失: %s", rec.Body.String())
	}
	return code, message, body.Error
}

func TestHealthzAndSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("healthz: %d %s", rec.Code, rec.Body.String())
	}
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control", "Strict-Transport-Security", "Referrer-Policy"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("缺少安全响应头 %s", hdr)
		}
	}
	if id := rec.Header().Get("X-Request-Id"); len(id) != 16 {
		t.Errorf("应生成 16 位请求 ID,实际 %q", id)
	}
}

func TestRequestIDPropagation(t *testing.T) {
	_, h := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "abc-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-Id") != "abc-123" {
		t.Fatalf("合规的上游请求 ID 应沿用")
	}
	req.Header.Set("X-Request-Id", "bad id\n")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-Id") == "bad id\n" {
		t.Fatalf("不合规的请求 ID 不应沿用")
	}
}

func TestReadyz(t *testing.T) {
	_, h := newTestServer(t, func(context.Context) error { return errors.New("db down: password=secret") })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("依赖不可用时应 503,实际 %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("就绪探针不得对外暴露失败细节: %s", rec.Body.String())
	}
}

func TestUnknownRouteReturnsProtocolError(t *testing.T) {
	_, h := newTestServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知路由应 404,实际 %d", rec.Code)
	}
	if code, _, _ := decodeError(t, rec); code != "not_found" {
		t.Fatalf("错误码应为 not_found,实际 %s", code)
	}
}

func TestAuthRequired(t *testing.T) {
	_, h := newTestServer(t, nil)
	for _, auth := range []string{"", "Basic abc", "Bearer ", "Bearer"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization=%q 应 401,实际 %d", auth, rec.Code)
		}
		if code, _, _ := decodeError(t, rec); code != "unauthorized" {
			t.Fatalf("错误码应为 unauthorized,实际 %s", code)
		}
	}
}

func TestWriteErrorFormat(t *testing.T) {
	s, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)

	rec := httptest.NewRecorder()
	s.writeError(rec, req, apierr.New(http.StatusBadRequest, apierr.CodeMissingChunks, "缺块").With("missing", []string{"a", "b"}))
	code, msg, fields := decodeError(t, rec)
	if rec.Code != http.StatusBadRequest || code != "missing_chunks" || msg != "缺块" {
		t.Fatalf("错误体不符: %d %s", rec.Code, rec.Body.String())
	}
	var missing []string
	if err := json.Unmarshal(fields["missing"], &missing); err != nil || len(missing) != 2 {
		t.Fatalf("附加字段应在 error 对象内: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.writeError(rec, req, apierr.New(http.StatusConflict, apierr.CodeVersionConflict, "冲突").With("head", nil))
	_, _, fields = decodeError(t, rec)
	if string(fields["head"]) != "null" {
		t.Fatalf("head 为空时应输出 null: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.writeError(rec, req, errors.New("pq: connection refused at 10.0.0.5"))
	code, msg, _ = decodeError(t, rec)
	if rec.Code != http.StatusInternalServerError || code != "internal" || strings.Contains(msg, "10.0.0.5") {
		t.Fatalf("内部错误不应回传细节: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPanicRecovery(t *testing.T) {
	s, _ := newTestServer(t, nil)
	h := s.observe(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic 应转成 500,实际 %d", rec.Code)
	}
	if code, _, _ := decodeError(t, rec); code != "internal" {
		t.Fatalf("错误码应为 internal,实际 %s", code)
	}
}

func TestDecodeJSON(t *testing.T) {
	type payload struct {
		A int `json:"a"`
	}
	cases := []struct {
		body   string
		limit  int64
		status int
	}{
		{`{"a":1}`, 100, 0},
		{`{"a":1}  `, 100, 0},
		{``, 100, http.StatusBadRequest},
		{`{"a":`, 100, http.StatusBadRequest},
		{`{"a":"x"}`, 100, http.StatusBadRequest},
		{`{"a":1}{"a":2}`, 100, http.StatusBadRequest},
		{`{"a":` + strings.Repeat("1", 200) + `}`, 100, http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		var p payload
		err := decodeJSON(rec, req, c.limit, &p)
		if c.status == 0 {
			if err != nil || p.A != 1 {
				t.Errorf("%q 应解析成功: %v", c.body, err)
			}
			continue
		}
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Status != c.status {
			t.Errorf("%q 应返回 %d,实际 %v", c.body, c.status, err)
		}
	}
}

func TestIPRateLimit(t *testing.T) {
	_, h := newTestServer(t, nil)
	var last *httptest.ResponseRecorder
	for i := 0; i < 31; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/prelogin", strings.NewReader(`不是 JSON`))
		req.RemoteAddr = "203.0.113.9:5555"
		last = httptest.NewRecorder()
		h.ServeHTTP(last, req)
		if i < 30 && last.Code != http.StatusBadRequest {
			t.Fatalf("第 %d 次应走到参数校验(400),实际 %d", i+1, last.Code)
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("第 31 次应 429,实际 %d", last.Code)
	}
	if code, _, _ := decodeError(t, last); code != "rate_limited" {
		t.Fatalf("错误码应为 rate_limited,实际 %s", code)
	}
	if ra, err := strconv.Atoi(last.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("应带 Retry-After 秒数,实际 %q", last.Header().Get("Retry-After"))
	}
	// 其它 IP 不受影响。
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/prelogin", strings.NewReader(`不是 JSON`))
	req.RemoteAddr = "203.0.113.10:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("其它 IP 不应被限流,实际 %d", rec.Code)
	}
}

func TestClientIP(t *testing.T) {
	s, _ := newTestServer(t, nil)
	s.proxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.1:1234", "", "203.0.113.1"},
		{"203.0.113.1:1234", "1.2.3.4", "203.0.113.1"},             // 直连来源不受信:忽略 XFF
		{"10.0.0.2:1234", "198.51.100.7", "198.51.100.7"},          // 受信代理转发
		{"10.0.0.2:1234", "6.6.6.6, 198.51.100.7", "198.51.100.7"}, // 左侧可伪造,取最右的不受信地址
		{"10.0.0.2:1234", "198.51.100.7, 10.0.0.3", "198.51.100.7"},
		{"10.0.0.2:1234", "", "10.0.0.2"},
		{"10.0.0.2:1234", "garbage", "10.0.0.2"},
		{"[::ffff:203.0.113.1]:1234", "", "203.0.113.1"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(req); got != c.want {
			t.Errorf("remote=%s xff=%q: 得到 %s,期望 %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestValidators(t *testing.T) {
	if e, err := normalizeEmail("  Foo@Example.COM "); err != nil || e != "foo@example.com" {
		t.Fatalf("邮箱应 trim + 小写: %q %v", e, err)
	}
	for _, bad := range []string{"", "a", "@b", "a@", "a b@c", "a@b@c"} {
		if _, err := normalizeEmail(bad); err == nil {
			t.Errorf("非法邮箱 %q 应被拒绝", bad)
		}
	}
	if _, err := decodeKey("authKey", strings.Repeat("A", 43)); err != nil {
		t.Fatalf("43 字符 base64url 即 32 字节: %v", err)
	}
	for _, bad := range []string{strings.Repeat("A", 43) + "=", strings.Repeat("A", 42), strings.Repeat("+", 43)} {
		if _, err := decodeKey("authKey", bad); err == nil {
			t.Errorf("%q 应被拒绝(须为无填充 base64url 且 32 字节)", bad)
		}
	}
	if !validChunkID(strings.Repeat("ab", 32)) || validChunkID(strings.Repeat("AB", 32)) || validChunkID("abc") {
		t.Fatalf("块 ID 应为 64 位小写十六进制")
	}
}

func TestPutChunkTooLarge(t *testing.T) {
	s, _ := newTestServer(t, nil)
	// 直接调用 handler(跳过认证),请求体超过 4 MiB + 64 字节应在读取阶段被拒绝。
	body := strings.NewReader(strings.Repeat("x", chunkBodyLimit+1))
	req := httptest.NewRequest(http.MethodPut, "/v1/chunks/"+strings.Repeat("a", 64), body)
	req.SetPathValue("chunkId", strings.Repeat("a", 64))
	rec := httptest.NewRecorder()
	s.putChunk(rec, req, service.Principal{})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大块应 413,实际 %d", rec.Code)
	}
	if code, _, _ := decodeError(t, rec); code != "payload_too_large" {
		t.Fatalf("错误码应为 payload_too_large,实际 %s", code)
	}
	_, _ = io.Copy(io.Discard, body)
}
