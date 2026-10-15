// Package api 是 Typoza 同步服务的 HTTP 客户端,覆盖 sync-protocol §4 的全部接口。
//
// 行为要点:
//   - 只允许 https;http 仅限 localhost / 127.0.0.1 / ::1(开发自测);
//   - 访问令牌过期(401 token_expired)时自动用刷新令牌换新并重试一次,同一时刻只有一个刷新请求在途;
//   - 令牌变化(注册、登录、恢复、刷新轮换)时回调 Options.OnTokens,由调用方持久化;
//   - 网络错误与 5xx 按指数退避加抖动重试,4xx 不重试;
//   - 非 2xx 响应解析为 *Error,用 errors.As 或 IsCode 判断错误码。
//
// Client 可被多个 goroutine 并发使用。
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRetries = 3
	// maxJSONBytes 限制 JSON 响应体大小,防止异常响应耗尽内存。
	maxJSONBytes = 64 << 20
	// maxChunkBytes 是单块密文上限(协议 §4.3:≤ 4 MiB + 64 字节)。
	maxChunkBytes = 4<<20 + 64
	// refreshTimeout 是单次刷新请求的超时。
	refreshTimeout = 30 * time.Second
)

// ErrNotLoggedIn 表示客户端没有可用的令牌,需要先登录。
var ErrNotLoggedIn = errors.New("api: 未登录(没有令牌)")

// errResponseTooLarge 表示响应体超过上限;属于服务器异常,不重试。
var errResponseTooLarge = errors.New("api: 响应体超过上限")

// Options 是 Client 的构造参数。
type Options struct {
	// BaseURL 是服务地址,如 "https://sync.example.com",不含 /v1。
	BaseURL string
	// HTTPClient 可选;为空时使用 5 分钟超时、不跟随重定向的默认客户端。
	HTTPClient *http.Client
	// MaxRetries 是网络错误与 5xx 的最大重试次数:0 用默认值 3,负数表示不重试。
	MaxRetries int
	// OnTokens 在客户端持有的令牌变化后调用(注册、登录、恢复、刷新轮换),
	// 调用方应把令牌持久化。回调在发起请求的 goroutine 中同步执行,不要在里面再调用本客户端。
	OnTokens func(TokenPair)
}

// Client 是同步服务客户端。
type Client struct {
	baseURL    string
	hc         *http.Client
	maxRetries int
	onTokens   func(TokenPair)

	// 退避参数;测试里调小以免拖慢用例。
	backoffBase  time.Duration
	backoffMax   time.Duration
	wsBackoffMin time.Duration
	wsBackoffMax time.Duration

	mu         sync.Mutex
	tokens     TokenPair
	refreshing *refreshCall
}

// refreshCall 代表一次在途的刷新;其他等待者读 err 前必须先等 done 关闭。
type refreshCall struct {
	done chan struct{}
	err  error
}

// New 校验地址并构造 Client。
func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("api: 解析服务地址 %q: %w", opts.BaseURL, err)
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("api: 服务地址 %q 不应带查询串或片段", opts.BaseURL)
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 5 * time.Minute,
			// 接口不会重定向;拒绝跟随,避免被引到非 https 地址。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	retries := opts.MaxRetries
	switch {
	case retries == 0:
		retries = defaultMaxRetries
	case retries < 0:
		retries = 0
	}
	return &Client{
		baseURL:      strings.TrimSuffix(u.String(), "/"),
		hc:           hc,
		maxRetries:   retries,
		onTokens:     opts.OnTokens,
		backoffBase:  500 * time.Millisecond,
		backoffMax:   30 * time.Second,
		wsBackoffMin: time.Second,
		wsBackoffMax: 60 * time.Second,
	}, nil
}

// checkScheme 只放行 https,http 仅限本机回环地址(协议 §3)。
func checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("api: 只允许 https,http 仅限 localhost/127.0.0.1/::1,当前为 %q", u.Host)
	default:
		return fmt.Errorf("api: 不支持的协议 %q,只允许 https", u.Scheme)
	}
}

// SetTokens 设置令牌(如应用启动时从钥匙串恢复)。不会触发 OnTokens。
func (c *Client) SetTokens(t TokenPair) {
	c.mu.Lock()
	c.tokens = t
	c.mu.Unlock()
}

// Tokens 返回当前令牌。
func (c *Client) Tokens() TokenPair {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens
}

func (c *Client) accessToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokens.AccessToken
}

// setTokens 更新令牌并通知调用方持久化。
func (c *Client) setTokens(t TokenPair) {
	c.SetTokens(t)
	if c.onTokens != nil {
		c.onTokens(t)
	}
}

type request struct {
	method      string
	path        string // 以 /v1 开头,路径参数已转义
	query       url.Values
	body        []byte
	contentType string
	auth        bool
	maxResp     int64
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// send 执行请求:处理认证、令牌刷新与重试,返回 2xx 响应或错误。
func (c *Client) send(ctx context.Context, r request) (*response, error) {
	refreshed := false
	for attempt := 0; ; {
		var access string
		if r.auth {
			access = c.accessToken()
			if access == "" {
				return nil, ErrNotLoggedIn
			}
		}
		resp, err := c.once(ctx, r, access)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("api: %s %s: %w", r.method, r.path, ctx.Err())
			}
			if !errors.Is(err, errResponseTooLarge) && attempt < c.maxRetries {
				if werr := c.backoff(ctx, attempt); werr != nil {
					return nil, fmt.Errorf("api: %s %s: %w", r.method, r.path, werr)
				}
				attempt++
				continue
			}
			return nil, fmt.Errorf("api: %s %s: %w", r.method, r.path, err)
		}
		if resp.status >= 200 && resp.status < 300 {
			return resp, nil
		}
		apiErr := parseError(resp.status, resp.header, resp.body)
		if r.auth && !refreshed && resp.status == http.StatusUnauthorized && apiErr.Code == CodeTokenExpired {
			if err := c.refresh(ctx, access); err != nil {
				return nil, fmt.Errorf("api: %s %s: 刷新令牌: %w", r.method, r.path, err)
			}
			refreshed = true
			continue
		}
		if resp.status >= 500 && attempt < c.maxRetries {
			if werr := c.backoff(ctx, attempt); werr != nil {
				return nil, fmt.Errorf("api: %s %s: %w", r.method, r.path, werr)
			}
			attempt++
			continue
		}
		return nil, fmt.Errorf("api: %s %s: %w", r.method, r.path, apiErr)
	}
}

// once 发出一次 HTTP 请求并读完响应体。
func (c *Client) once(ctx context.Context, r request, access string) (*response, error) {
	u := c.baseURL + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u, body)
	if err != nil {
		return nil, fmt.Errorf("构造请求: %w", err)
	}
	if r.body != nil {
		req.Header.Set("Content-Type", r.contentType)
	}
	if access != "" {
		req.Header.Set("Authorization", "Bearer "+access)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, r.maxResp+1))
	if err != nil {
		return nil, fmt.Errorf("读取响应: %w", err)
	}
	if int64(len(data)) > r.maxResp {
		return nil, fmt.Errorf("%w(%d 字节)", errResponseTooLarge, r.maxResp)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: data}, nil
}

// backoff 按 attempt 指数退避并加抖动:等待时间落在 [d/2, d],d = base·2^attempt,上限 backoffMax。
func (c *Client) backoff(ctx context.Context, attempt int) error {
	return sleepCtx(ctx, jitter(capDouble(c.backoffBase, attempt, c.backoffMax)))
}

func capDouble(base time.Duration, n int, limit time.Duration) time.Duration {
	d := base
	for i := 0; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	return d/2 + rand.N(d/2+1)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// refresh 用刷新令牌换新令牌。stale 是触发刷新的那个访问令牌:
// 如果当前令牌已经不是它,说明别的请求刚刷新过,直接返回让调用方重试。
// 同一时刻只有一个刷新请求在途,其余调用者等待它的结果(协议 §3.1)。
func (c *Client) refresh(ctx context.Context, stale string) error {
	c.mu.Lock()
	if c.tokens.AccessToken != stale {
		c.mu.Unlock()
		return nil
	}
	if call := c.refreshing; call != nil {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	call := &refreshCall{done: make(chan struct{})}
	c.refreshing = call
	rt := c.tokens.RefreshToken
	c.mu.Unlock()

	// 刷新请求不随调用方取消:服务器可能已经轮换了令牌,中途放弃会丢掉新令牌,
	// 下次再用旧令牌刷新就会被判定为重放,整台设备被登出。
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	pair, err := c.doRefresh(rctx, rt)
	cancel()

	c.mu.Lock()
	if err == nil {
		c.tokens = pair
	}
	c.refreshing = nil
	c.mu.Unlock()
	call.err = err
	close(call.done)

	if err == nil && c.onTokens != nil {
		c.onTokens(pair)
	}
	return err
}

// doRefresh 调 POST /v1/auth/refresh。不做自动重试:刷新令牌一次性,
// 若首个请求其实已到达服务器,重发旧令牌只会触发重放检测。
func (c *Client) doRefresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	if refreshToken == "" {
		return TokenPair{}, ErrNotLoggedIn
	}
	body, err := json.Marshal(map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return TokenPair{}, fmt.Errorf("api: 序列化刷新请求: %w", err)
	}
	resp, err := c.once(ctx, request{
		method: http.MethodPost, path: "/v1/auth/refresh", body: body,
		contentType: jsonContentType, maxResp: maxJSONBytes,
	}, "")
	if err != nil {
		return TokenPair{}, fmt.Errorf("api: POST /v1/auth/refresh: %w", err)
	}
	if resp.status != http.StatusOK {
		return TokenPair{}, fmt.Errorf("api: POST /v1/auth/refresh: %w", parseError(resp.status, resp.header, resp.body))
	}
	var pair TokenPair
	if err := json.Unmarshal(resp.body, &pair); err != nil {
		return TokenPair{}, fmt.Errorf("api: 解析刷新响应: %w", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		return TokenPair{}, errors.New("api: 刷新响应缺少令牌")
	}
	return pair, nil
}

const jsonContentType = "application/json; charset=utf-8"

// doJSON 发送 JSON 请求并把响应解析进 out(out 为 nil 时忽略响应体)。
func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, in, out any, auth bool) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return fmt.Errorf("api: 序列化 %s %s 请求: %w", method, path, err)
		}
	}
	resp, err := c.send(ctx, request{
		method: method, path: path, query: query, body: body,
		contentType: jsonContentType, auth: auth, maxResp: maxJSONBytes,
	})
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(resp.body, out); err != nil {
			return fmt.Errorf("api: 解析 %s %s 响应: %w", method, path, err)
		}
	}
	return nil
}
