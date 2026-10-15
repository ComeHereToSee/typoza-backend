package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/coder/websocket"
)

// EventHandlers 是事件订阅的回调。回调在订阅 goroutine 中同步执行,应尽快返回。
type EventHandlers struct {
	// OnEvent 收到服务器推送的事件时调用。
	OnEvent func(Event)
	// OnReconnect 在每次连接建立成功后调用(含首次连接)。通知只是「有新东西」的提示,
	// 断线期间的通知会丢失,调用方应借此全量补拉一次(协议 §4.5)。
	OnReconnect func()
	// OnError 在连接失败或断开时调用,随后自动退避重连;可为 nil。
	OnError func(error)
}

// SubscribeEvents 订阅 GET /v1/events,断线后按 1s 起、上限 60s 的指数退避加抖动重连。
// 阻塞直到 ctx 取消(返回 ctx.Err())或登录态失效(返回对应的 *Error,重连无意义)。
func (c *Client) SubscribeEvents(ctx context.Context, h EventHandlers) error {
	wait := c.wsBackoffMin
	for {
		connected, err := c.listenOnce(ctx, h)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrNotLoggedIn) || IsAuthError(err) {
			return err
		}
		if err != nil && h.OnError != nil {
			h.OnError(err)
		}
		if connected {
			// 连上过说明网络恢复了,下次从最短间隔开始。
			wait = c.wsBackoffMin
		}
		if err := sleepCtx(ctx, jitter(wait)); err != nil {
			return err
		}
		if !connected {
			wait = min(wait*2, c.wsBackoffMax)
		}
	}
}

// listenOnce 建立一次连接并读到断开为止;connected 表示握手是否成功过。
func (c *Client) listenOnce(ctx context.Context, h EventHandlers) (connected bool, err error) {
	conn, err := c.dialEvents(ctx)
	if err != nil {
		return false, err
	}
	defer conn.CloseNow()
	if h.OnReconnect != nil {
		h.OnReconnect()
	}
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return true, fmt.Errorf("api: 事件连接断开: %w", err)
		}
		if typ != websocket.MessageText {
			continue
		}
		var ev Event
		if err := json.Unmarshal(data, &ev); err != nil {
			if h.OnError != nil {
				h.OnError(fmt.Errorf("api: 解析事件 %q: %w", data, err))
			}
			continue
		}
		if h.OnEvent != nil {
			h.OnEvent(ev)
		}
	}
}

// dialEvents 带 Authorization 头握手;访问令牌过期时刷新一次再握手。
func (c *Client) dialEvents(ctx context.Context) (*websocket.Conn, error) {
	refreshed := false
	for {
		access := c.accessToken()
		if access == "" {
			return nil, ErrNotLoggedIn
		}
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+access)
		// 握手超时由 HTTPClient.Timeout 控制(库内只把它用于握手阶段)。
		conn, resp, err := websocket.Dial(ctx, c.baseURL+"/v1/events", &websocket.DialOptions{
			HTTPClient: c.hc,
			HTTPHeader: hdr,
		})
		if err == nil {
			return conn, nil
		}
		if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
			return nil, fmt.Errorf("api: 连接事件通道: %w", err)
		}
		var body []byte
		if resp.Body != nil {
			body, _ = io.ReadAll(resp.Body) // 库已把响应体截成前 1024 字节的内存副本
		}
		apiErr := parseError(resp.StatusCode, resp.Header, body)
		if !refreshed && resp.StatusCode == http.StatusUnauthorized && apiErr.Code == CodeTokenExpired {
			if err := c.refresh(ctx, access); err != nil {
				return nil, fmt.Errorf("api: 事件通道刷新令牌: %w", err)
			}
			refreshed = true
			continue
		}
		return nil, fmt.Errorf("api: 连接事件通道: %w", apiErr)
	}
}
