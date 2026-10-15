package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// events 是 WebSocket 实时通知(协议 §4.5):推送 vault.changed,每 30 秒 ping 一次。
// 每次 ping 前顺带确认设备仍处于登录状态,登出或被吊销的设备连接会被主动断开。
// 服务停机时(Hub 关闭)以 1001 going away 断开,客户端按协议退避重连。
func (s *Server) events(w http.ResponseWriter, r *http.Request, p service.Principal) {
	// 原生客户端不带 Origin;浏览器跨站发起的连接由默认的同源检查拒绝。
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		s.log.Warn("WebSocket 握手失败", "requestId", requestInfo(r).id, "err", err)
		return
	}
	defer func() { _ = c.CloseNow() }() // 正常路径已发过关闭帧,这里只确保底层连接释放

	s.metrics.WSConnections.Inc()
	defer s.metrics.WSConnections.Dec()

	sub := s.hub.Subscribe(p.UserID)
	defer sub.Close()

	// 客户端不应发数据帧;CloseRead 在后台读取以处理 pong 与关闭帧,连接断开时取消 ctx。
	ctx := c.CloseRead(r.Context())
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.hub.Done():
			_ = c.Close(websocket.StatusGoingAway, "server shutting down")
			return
		case ev := <-sub.C():
			b, err := json.Marshal(ev)
			if err != nil {
				s.log.Error("编码通知失败", "err", err)
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
			err = c.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		case <-ticker.C:
			active, err := s.svc.DeviceActive(ctx, p)
			if err != nil {
				// 数据库短暂故障不应把所有在线客户端踢下线;下一轮再查。
				s.log.Warn("检查设备状态失败", "userId", p.UserID, "err", err)
			} else if !active {
				_ = c.Close(websocket.StatusPolicyViolation, "device signed out")
				return
			}
			pctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
			err = c.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
