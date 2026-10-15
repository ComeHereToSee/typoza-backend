package notify

import (
	"encoding/json"
	"testing"
)

func TestHubDeliversOnlyToSameUser(t *testing.T) {
	h := NewHub()
	a := h.Subscribe("user-a")
	defer a.Close()
	b := h.Subscribe("user-b")
	defer b.Close()

	h.Publish(Message{UserID: "user-a", VaultID: "v1", Seq: 7})
	select {
	case ev := <-a.C():
		if ev.Type != "vault.changed" || ev.VaultID != "v1" || ev.Seq != 7 {
			t.Fatalf("事件内容不符: %+v", ev)
		}
	default:
		t.Fatalf("user-a 应收到通知")
	}
	select {
	case ev := <-b.C():
		t.Fatalf("user-b 不应收到 user-a 的通知: %+v", ev)
	default:
	}
}

func TestHubDoesNotBlockWhenBufferFull(t *testing.T) {
	h := NewHub()
	s := h.Subscribe("u")
	defer s.Close()
	for i := range subBuffer * 3 {
		h.Publish(Message{UserID: "u", VaultID: "v", Seq: int64(i)})
	}
	if len(s.C()) != subBuffer {
		t.Fatalf("缓冲应满 %d 条,实际 %d", subBuffer, len(s.C()))
	}
}

func TestSubscriptionCloseRemoves(t *testing.T) {
	h := NewHub()
	s := h.Subscribe("u")
	s.Close()
	s.Close() // 幂等
	h.Publish(Message{UserID: "u", VaultID: "v", Seq: 1})
	if len(s.C()) != 0 {
		t.Fatalf("取消订阅后不应再收到通知")
	}
	if len(h.subs) != 0 {
		t.Fatalf("空订阅集合应被清理")
	}
}

func TestHubCloseSignalsDone(t *testing.T) {
	h := NewHub()
	h.Close()
	h.Close()
	select {
	case <-h.Done():
	default:
		t.Fatalf("Close 后 Done 应已关闭")
	}
}

func TestPayloadAndEventJSON(t *testing.T) {
	p, err := Payload("u", "v", 57)
	if err != nil {
		t.Fatal(err)
	}
	var m Message
	if err := json.Unmarshal([]byte(p), &m); err != nil || m.UserID != "u" || m.VaultID != "v" || m.Seq != 57 {
		t.Fatalf("载荷往返失败: %s %v", p, err)
	}
	b, _ := json.Marshal(Event{Type: "vault.changed", VaultID: "v", Seq: 57})
	if string(b) != `{"type":"vault.changed","vaultId":"v","seq":57}` {
		t.Fatalf("推送消息格式不符合协议: %s", b)
	}
}
