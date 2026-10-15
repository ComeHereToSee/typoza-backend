package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func newTestClient(t *testing.T, url string, onTokens func(TokenPair)) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: url, OnTokens: onTokens})
	if err != nil {
		t.Fatal(err)
	}
	c.backoffBase = time.Millisecond
	c.backoffMax = 5 * time.Millisecond
	c.wsBackoffMin = 5 * time.Millisecond
	c.wsBackoffMax = 20 * time.Millisecond
	return c
}

func writeErr(w http.ResponseWriter, status int, code string, extra map[string]any) {
	e := map[string]any{"code": code, "message": code}
	for k, v := range extra {
		e[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": e})
}

func TestNew_SchemePolicy(t *testing.T) {
	ok := []string{"https://sync.example.com", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:9"}
	for _, u := range ok {
		if _, err := New(Options{BaseURL: u}); err != nil {
			t.Errorf("%s 应允许: %v", u, err)
		}
	}
	bad := []string{"http://sync.example.com", "http://192.168.1.2", "ftp://x", "ws://localhost", "https://x?a=1"}
	for _, u := range bad {
		if _, err := New(Options{BaseURL: u}); err == nil {
			t.Errorf("%s 应拒绝", u)
		}
	}
}

func TestB64_JSON(t *testing.T) {
	data, err := json.Marshal(struct {
		V B64 `json:"v"`
	}{B64{0xfb, 0xff}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"v":"-_8"}` {
		t.Fatalf("应为 base64url 无填充: %s", data)
	}
	var out struct {
		V B64 `json:"v"`
	}
	if err := json.Unmarshal([]byte(`{"v":"-_8"}`), &out); err != nil || len(out.V) != 2 || out.V[0] != 0xfb {
		t.Fatalf("解码失败: %v %x", err, out.V)
	}
	for _, bad := range []string{`{"v":"-_8="}`, `{"v":"+/8"}`, `{"v":1}`} {
		if err := json.Unmarshal([]byte(bad), &out); err == nil {
			t.Errorf("%s 应解码失败", bad)
		}
	}
}

func TestErrorParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commit"):
			writeErr(w, 409, CodeVersionConflict, map[string]any{"head": map[string]any{
				"fileId": "f", "version": 7, "seq": 70, "manifest": "AQI", "deleted": false, "size": 3,
				"deviceId": "d", "createdAt": "2026-10-16T01:02:03.123Z",
			}})
		case r.URL.Path == "/v1/chunks/check":
			writeErr(w, 400, CodeMissingChunks, map[string]any{"missing": []string{"aa", "bb"}})
		case r.URL.Path == "/v1/vaults":
			w.Header().Set("Retry-After", "7")
			writeErr(w, 429, CodeRateLimited, nil)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("not json"))
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)
	c.SetTokens(TokenPair{AccessToken: "a", RefreshToken: "r"})
	ctx := context.Background()

	_, err := c.Commit(ctx, "v", "f", CommitRequest{BaseVersion: 1})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeVersionConflict || e.Head == nil || e.Head.Version != 7 || string(e.Head.Manifest) != "\x01\x02" {
		t.Fatalf("409 解析错误: %v %+v", err, e)
	}
	_, err = c.CheckChunks(ctx, []string{"aa"})
	if !errors.As(err, &e) || e.Code != CodeMissingChunks || len(e.Missing) != 2 {
		t.Fatalf("missing_chunks 解析错误: %v", err)
	}
	_, err = c.Vaults(ctx)
	if !errors.As(err, &e) || e.Status != 429 || e.RetryAfter != 7*time.Second || !IsCode(err, CodeRateLimited) {
		t.Fatalf("429 解析错误: %v", err)
	}
	_, err = c.Account(ctx)
	if !errors.As(err, &e) || e.Status != 400 || e.Code != "" || e.Message != "not json" {
		t.Fatalf("非协议错误体: %v", err)
	}
}

func TestRetry5xxButNot4xx(t *testing.T) {
	var calls5, calls4 atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/account":
			if calls5.Add(1) <= 2 {
				writeErr(w, 503, CodeInternal, nil)
				return
			}
			_ = json.NewEncoder(w).Encode(Account{Email: "a@b.c"})
		default:
			calls4.Add(1)
			writeErr(w, 403, CodeForbidden, nil)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, nil)
	c.SetTokens(TokenPair{AccessToken: "a", RefreshToken: "r"})
	acc, err := c.Account(context.Background())
	if err != nil || acc.Email != "a@b.c" || calls5.Load() != 3 {
		t.Fatalf("5xx 应重试后成功: %v calls=%d", err, calls5.Load())
	}
	if _, err := c.Vaults(context.Background()); !IsCode(err, CodeForbidden) || calls4.Load() != 1 {
		t.Fatalf("4xx 不应重试: %v calls=%d", err, calls4.Load())
	}

	// 重试次数用尽后返回最后的错误。
	calls5.Store(-100)
	if _, err := c.Account(context.Background()); !IsCode(err, CodeInternal) {
		t.Fatalf("重试用尽应返回 5xx 错误: %v", err)
	}
}

func TestRefresh_SingleFlightAndRotation(t *testing.T) {
	var refreshCalls atomic.Int32
	var mu sync.Mutex
	valid := map[string]bool{"new-access": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/refresh" {
			refreshCalls.Add(1)
			var in struct {
				RefreshToken string `json:"refreshToken"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.RefreshToken != "old-refresh" {
				writeErr(w, 401, CodeRefreshReuse, nil)
				return
			}
			time.Sleep(50 * time.Millisecond) // 拉长窗口,让并发请求都撞上过期
			_ = json.NewEncoder(w).Encode(TokenPair{AccessToken: "new-access", AccessTokenExpiresIn: 900, RefreshToken: "new-refresh"})
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := valid[tok]
		mu.Unlock()
		if !ok {
			writeErr(w, 401, CodeTokenExpired, nil)
			return
		}
		_ = json.NewEncoder(w).Encode(Account{Email: "a@b.c"})
	}))
	defer srv.Close()

	var gotTokens []TokenPair
	var tmu sync.Mutex
	c := newTestClient(t, srv.URL, func(p TokenPair) {
		tmu.Lock()
		gotTokens = append(gotTokens, p)
		tmu.Unlock()
	})
	c.SetTokens(TokenPair{AccessToken: "old-access", RefreshToken: "old-refresh"})

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Account(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发请求失败: %v", err)
		}
	}
	if n := refreshCalls.Load(); n != 1 {
		t.Fatalf("刷新请求应只发 1 次,实际 %d", n)
	}
	if len(gotTokens) != 1 || gotTokens[0].RefreshToken != "new-refresh" {
		t.Fatalf("OnTokens 应回调 1 次新令牌: %+v", gotTokens)
	}
	if c.Tokens().RefreshToken != "new-refresh" {
		t.Fatal("客户端未保存轮换后的刷新令牌")
	}

	// 刷新令牌被判重放:返回认证错误,调用方需要重新登录。
	mu.Lock()
	valid = map[string]bool{}
	mu.Unlock()
	_, err := c.Account(context.Background())
	if !IsAuthError(err) || !IsCode(err, CodeRefreshReuse) {
		t.Fatalf("重放应返回 refresh_reuse 认证错误: %v", err)
	}
}

func TestSubscribeEvents(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ws-access" {
			writeErr(w, 401, CodeUnauthorized, nil)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		n := conns.Add(1)
		ctx := c.CloseRead(r.Context())
		_ = wsjson.Write(ctx, c, Event{Type: EventVaultChanged, VaultID: "v1", Seq: int64(n)})
		if n == 1 {
			// 第一次连接发完就断开,验证客户端会重连。
			_ = c.Close(websocket.StatusGoingAway, "bye")
			return
		}
		<-ctx.Done()
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	c.SetTokens(TokenPair{AccessToken: "ws-access", RefreshToken: "r"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan Event, 10)
	var reconnects atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- c.SubscribeEvents(ctx, EventHandlers{
			OnEvent:     func(e Event) { events <- e },
			OnReconnect: func() { reconnects.Add(1) },
		})
	}()
	for want := int64(1); want <= 2; want++ {
		select {
		case e := <-events:
			if e.Type != EventVaultChanged || e.VaultID != "v1" || e.Seq != want {
				t.Fatalf("事件不对: %+v", e)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("等待第 %d 个事件超时", want)
		}
	}
	if reconnects.Load() < 2 {
		t.Fatalf("断线重连后应再次回调 OnReconnect,实际 %d 次", reconnects.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled: %v", err)
	}

	// 令牌无效(非过期):订阅直接返回认证错误,不无限重连。
	c.SetTokens(TokenPair{AccessToken: "bad", RefreshToken: "r"})
	err := c.SubscribeEvents(context.Background(), EventHandlers{})
	if !IsAuthError(err) {
		t.Fatalf("应返回认证错误: %v", err)
	}
}
