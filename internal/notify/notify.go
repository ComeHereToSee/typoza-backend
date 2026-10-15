// Package notify 负责「库有新变更」的实时提示:
// 提交事务里 pg_notify → 每个实例 LISTEN 同一频道 → 进程内 Hub 按账号分发给 WebSocket 连接。
//
// 通知只是提示,丢了也不影响正确性:客户端收到后走 changes 接口拉取,断线重连后先全量补拉(协议 §4.5)。
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Channel 是 PostgreSQL NOTIFY 频道名。频道按数据库全局生效;载荷里带 userId,
// 订阅端按账号过滤,因此同库多 schema(并行测试)互相串到的通知会被自然丢弃。
const Channel = "typoza_vault_changed"

// subBuffer 是每个订阅的缓冲。缓冲满时丢弃新通知是安全的:
// 缓冲里已有待处理的通知,客户端处理它们时拉取的 changes 一定覆盖被丢的那次提交。
const subBuffer = 16

// Event 是推给客户端的消息(协议 §4.5)。
type Event struct {
	Type    string `json:"type"`
	VaultID string `json:"vaultId"`
	Seq     int64  `json:"seq"`
}

// Message 是跨实例广播的载荷。
type Message struct {
	UserID  string `json:"userId"`
	VaultID string `json:"vaultId"`
	Seq     int64  `json:"seq"`
}

// Payload 序列化广播载荷,供提交事务里的 pg_notify 使用。
func Payload(userID, vaultID string, seq int64) (string, error) {
	b, err := json.Marshal(Message{UserID: userID, VaultID: vaultID, Seq: seq})
	if err != nil {
		return "", fmt.Errorf("序列化通知载荷: %w", err)
	}
	return string(b), nil
}

// Hub 是进程内订阅中心。
type Hub struct {
	mu     sync.Mutex
	subs   map[string]map[*Subscription]struct{}
	closed chan struct{}
	once   sync.Once
}

// Subscription 是一个连接对某账号的订阅。
type Subscription struct {
	hub    *Hub
	userID string
	ch     chan Event
}

// NewHub 创建订阅中心。
func NewHub() *Hub {
	return &Hub{subs: map[string]map[*Subscription]struct{}{}, closed: make(chan struct{})}
}

// Subscribe 订阅 userID 的通知;用完必须 Close。
func (h *Hub) Subscribe(userID string) *Subscription {
	s := &Subscription{hub: h, userID: userID, ch: make(chan Event, subBuffer)}
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.subs[userID]
	if set == nil {
		set = map[*Subscription]struct{}{}
		h.subs[userID] = set
	}
	set[s] = struct{}{}
	return s
}

// C 返回通知通道。
func (s *Subscription) C() <-chan Event { return s.ch }

// Close 取消订阅(幂等)。
func (s *Subscription) Close() {
	h := s.hub
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.subs[s.userID]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(h.subs, s.userID)
		}
	}
}

// Publish 把通知分发给该账号的全部本地订阅;不阻塞。
func (h *Hub) Publish(msg Message) {
	ev := Event{Type: "vault.changed", VaultID: msg.VaultID, Seq: msg.Seq}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs[msg.UserID] {
		select {
		case s.ch <- ev:
		default:
		}
	}
}

// Done 在 Hub 关闭(服务停机)后关闭,WebSocket 连接据此主动断开。
func (h *Hub) Done() <-chan struct{} { return h.closed }

// Close 通知所有连接服务即将停止。
func (h *Hub) Close() {
	h.once.Do(func() { close(h.closed) })
}

// Listen 维持一条专用连接 LISTEN 频道,把收到的通知转给 hub;连接断开后指数退避重连,直到 ctx 取消。
// onReconnect 在每次重连前调用(用于计数指标),可为 nil。
func Listen(ctx context.Context, databaseURL string, hub *Hub, log *slog.Logger, onReconnect func()) {
	backoff := time.Second
	for {
		err := listenOnce(ctx, databaseURL, hub, log)
		if ctx.Err() != nil {
			return
		}
		log.Error("通知监听连接中断,稍后重连", "err", err, "backoff", backoff.String())
		if onReconnect != nil {
			onReconnect()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func listenOnce(ctx context.Context, databaseURL string, hub *Hub, log *slog.Logger) (err error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("连接数据库: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(context.WithoutCancel(ctx)); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("等待通知: %w", err)
		}
		var msg Message
		if err := json.Unmarshal([]byte(n.Payload), &msg); err != nil {
			log.Error("丢弃无法解析的通知载荷", "err", err)
			continue
		}
		hub.Publish(msg)
	}
}
