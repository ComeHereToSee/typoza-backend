package account

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/fakeserver"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	fs := fakeserver.New()
	srv := httptest.NewServer(fs.Handler())
	t.Cleanup(func() {
		fs.Close()
		srv.Close()
	})
	return srv
}

func newClient(t *testing.T, url string) *api.Client {
	t.Helper()
	c, err := api.New(api.Options{BaseURL: url})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var dev = api.Device{Name: "测试 Mac", Platform: "macos"}

func TestRegisterLoginChangePasswordRecover(t *testing.T) {
	ctx := context.Background()
	srv := newServer(t)

	var persisted []api.TokenPair
	c1, err := api.New(api.Options{BaseURL: srv.URL, OnTokens: func(p api.TokenPair) { persisted = append(persisted, p) }})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := Register(ctx, c1, "  Alice@Example.COM ", "第一个密码", dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(reg.RecoveryCode, "-")) != 13 {
		t.Fatalf("恢复码格式不对: %s", reg.RecoveryCode)
	}
	if len(persisted) != 1 || persisted[0].RefreshToken == "" {
		t.Fatalf("注册后应回调 OnTokens: %+v", persisted)
	}
	if _, err := Register(ctx, newClient(t, srv.URL), "alice@example.com", "x", dev); !api.IsCode(err, api.CodeEmailTaken) {
		t.Fatalf("重复注册应返回 email_taken: %v", err)
	}

	// 第二台设备登录(邮箱大小写与空白规范化),拿到相同的账户密钥。
	c2 := newClient(t, srv.URL)
	s2, err := Login(ctx, c2, "alice@example.com", "第一个密码", LoginOptions{Device: dev})
	if err != nil {
		t.Fatal(err)
	}
	if s2.Keys.Account != reg.Keys.Account || s2.Keys.Meta != reg.Keys.Meta {
		t.Fatal("两台设备解出的账户密钥不同")
	}
	if s2.DeviceID == reg.DeviceID {
		t.Fatal("第二台设备应是新设备记录")
	}
	if _, err := Login(ctx, newClient(t, srv.URL), "alice@example.com", "错误密码", LoginOptions{Device: dev}); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("错误密码应返回 unauthorized: %v", err)
	}

	// 设备列表与吊销:第三台设备登录后被第一台吊销,其令牌随即失效。
	c3 := newClient(t, srv.URL)
	old3, err := Login(ctx, c3, "alice@example.com", "第一个密码", LoginOptions{Device: api.Device{Name: "旧电脑", Platform: "macos"}})
	if err != nil {
		t.Fatal(err)
	}
	devs, err := c1.Devices(ctx)
	if err != nil || len(devs) != 3 {
		t.Fatalf("应有 3 台设备: %+v %v", devs, err)
	}
	for _, d := range devs {
		if d.Current != (d.ID == reg.DeviceID) {
			t.Fatalf("current 标记不对: %+v", d)
		}
		if d.ID == old3.DeviceID && d.Name != "旧电脑" {
			t.Fatalf("设备名不对: %+v", d)
		}
	}
	if err := c1.RevokeDevice(ctx, old3.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := c3.Account(ctx); !api.IsAuthError(err) {
		t.Fatalf("被吊销的设备应失去登录态: %v", err)
	}
	if devs, _ = c1.Devices(ctx); len(devs) != 2 {
		t.Fatalf("吊销后应剩 2 台设备: %+v", devs)
	}

	// 改主密码:旧密码失效,新密码可用且账户密钥不变。
	if err := ChangePassword(ctx, c1, "alice@example.com", "第一个密码", "第二个密码", reg.Keys); err != nil {
		t.Fatal(err)
	}
	if _, err := Login(ctx, newClient(t, srv.URL), "alice@example.com", "第一个密码", LoginOptions{Device: dev}); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("改密后旧密码应失败: %v", err)
	}
	s3, err := Login(ctx, newClient(t, srv.URL), "alice@example.com", "第二个密码", LoginOptions{Device: dev})
	if err != nil || s3.Keys.Account != reg.Keys.Account {
		t.Fatalf("改密后新密码登录失败或密钥变化: %v", err)
	}
	// 改密吊销了其他设备:c2 的令牌失效。
	if _, err := c2.Account(ctx); !api.IsAuthError(err) {
		t.Fatalf("改密后其他设备应被登出: %v", err)
	}

	// 恢复码重置主密码(大小写、空白不敏感)。
	code := strings.ToLower(strings.ReplaceAll(reg.RecoveryCode, "-", " "))
	s4, err := Recover(ctx, newClient(t, srv.URL), "alice@example.com", code, "第三个密码", dev)
	if err != nil {
		t.Fatal(err)
	}
	if s4.Keys.Account != reg.Keys.Account {
		t.Fatal("恢复后账户密钥应不变")
	}
	if _, err := Login(ctx, newClient(t, srv.URL), "alice@example.com", "第二个密码", LoginOptions{Device: dev}); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("恢复后旧密码应失败: %v", err)
	}
	if s5, err := Login(ctx, newClient(t, srv.URL), "alice@example.com", "第三个密码", LoginOptions{Device: dev}); err != nil || s5.Keys.Account != reg.Keys.Account {
		t.Fatalf("恢复后新密码登录失败: %v", err)
	}
	// 错误恢复码。
	other := crypto.FormatRecoveryCode(crypto.NewRecoveryKey())
	if _, err := Recover(ctx, newClient(t, srv.URL), "alice@example.com", other, "x", dev); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("错误恢复码应失败: %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	ctx := context.Background()
	c := newClient(t, "http://127.0.0.1:1")
	if _, err := Register(ctx, c, " ", "pw", dev); !errors.Is(err, ErrEmptyEmail) {
		t.Fatalf("空邮箱: %v", err)
	}
	if _, err := Login(ctx, c, "a@b.c", "", LoginOptions{}); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("空密码: %v", err)
	}
	if _, err := Recover(ctx, c, "a@b.c", "not-a-code", "pw", dev); err == nil {
		t.Fatal("非法恢复码应报错")
	}
}

func TestRejectWeakServerKDF(t *testing.T) {
	weak := []api.KDF{
		{Algorithm: "argon2id", MemoryKiB: 1024, Iterations: 3, Parallelism: 4, Salt: make([]byte, 16)},
		{Algorithm: "argon2id", MemoryKiB: 65536, Iterations: 1, Parallelism: 4, Salt: make([]byte, 16)},
		{Algorithm: "argon2id", MemoryKiB: 65536, Iterations: 3, Parallelism: 300, Salt: make([]byte, 16)},
		{Algorithm: "scrypt", MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: make([]byte, 16)},
	}
	for i, k := range weak {
		if _, err := fromAPIKDF(k); err == nil {
			t.Errorf("case %d 应拒绝: %+v", i, k)
		}
	}
}
