package app_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/auth"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

func TestRegisterLoginRefreshLogout(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	s := u.session
	if s.UserID == "" || s.DeviceID == "" || s.AccessTokenExpiresIn != 900 || !strings.HasPrefix(s.RefreshToken, "tzr_") {
		t.Fatalf("会话对象不符合协议: %+v", s)
	}
	if s.EncryptedAccountKey != u.wrapped || s.KDF != u.kdf {
		t.Fatalf("会话应原样回传 encryptedAccountKey 与 kdf")
	}

	var acc service.Account
	e.call(http.MethodGet, "/v1/account", s.AccessToken, nil, http.StatusOK, &acc)
	if acc.UserID != s.UserID || acc.Email != u.email || acc.TOTPEnabled || acc.Usage.QuotaBytes != e.cfg.QuotaBytes {
		t.Fatalf("账号信息不符: %+v", acc)
	}

	// 重复注册、错误口令、未注册邮箱。
	e.expectError(http.MethodPost, "/v1/auth/register", "", map[string]any{
		"email": strings.ToUpper(u.email), "kdf": u.kdf, "authKey": b64(u.authKey), "encryptedAccountKey": u.wrapped,
		"recoveryAuthKey": b64(u.recoveryKey), "recoveryEncryptedAccountKey": u.wrapped, "device": device("x"),
	}, http.StatusConflict, "email_taken")
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(randBytes(t, 32)), "device": device("x"),
	}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": uniqueEmail(t), "authKey": b64(u.authKey), "device": device("x"),
	}, http.StatusUnauthorized, "unauthorized")

	// 第二台设备登录;邮箱大小写与空白不敏感。
	u.email = "  " + strings.ToUpper(u.email) + " "
	s2 := e.login(u, "设备 B", nil)
	if s2.UserID != s.UserID || s2.DeviceID == s.DeviceID {
		t.Fatalf("第二台设备应是同一账号的新设备")
	}

	// 刷新:轮换出新令牌,旧令牌作废。
	var t1 tokens
	r := e.refresh(s.RefreshToken)
	if r.status != http.StatusOK {
		t.Fatalf("刷新失败: %d %s", r.status, r.body)
	}
	decodeInto(t, r.body, &t1)
	if t1.RefreshToken == s.RefreshToken || t1.AccessTokenExpiresIn != 900 {
		t.Fatalf("刷新应轮换令牌: %+v", t1)
	}
	e.call(http.MethodGet, "/v1/account", t1.AccessToken, nil, http.StatusOK, nil)

	// 旧令牌重放 → refresh_reuse,整条链(含刚轮换出的新令牌)被吊销,设备访问令牌立即失效。
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": s.RefreshToken}, http.StatusUnauthorized, "refresh_reuse")
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": t1.RefreshToken}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodGet, "/v1/account", t1.AccessToken, nil, http.StatusUnauthorized, "unauthorized")

	// 另一台设备不受影响;登出后其令牌全部失效。
	e.call(http.MethodGet, "/v1/account", s2.AccessToken, nil, http.StatusOK, nil)
	e.call(http.MethodPost, "/v1/auth/logout", s2.AccessToken, nil, http.StatusNoContent, nil)
	e.expectError(http.MethodGet, "/v1/account", s2.AccessToken, nil, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": s2.RefreshToken}, http.StatusUnauthorized, "unauthorized")

	// 格式错误的刷新令牌。
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": "tzr_short"}, http.StatusUnauthorized, "unauthorized")
}

func TestLoginReusesDeviceID(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	s := e.login(u, "设备 A(重装)", map[string]any{"deviceId": u.session.DeviceID})
	if s.DeviceID != u.session.DeviceID {
		t.Fatalf("带本账号 deviceId 登录应复用设备记录")
	}
	// 复用设备时吊销其旧令牌链。
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": u.session.RefreshToken}, http.StatusUnauthorized, "unauthorized")
	// 他人的 / 不存在的 deviceId → 新建设备。
	s2 := e.login(u, "设备 C", map[string]any{"deviceId": newUUID(t)})
	if s2.DeviceID == s.DeviceID {
		t.Fatalf("未知 deviceId 应新建设备")
	}
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(u.authKey), "device": device("x"), "deviceId": "NOT-A-UUID",
	}, http.StatusBadRequest, "invalid_request")
}

func TestPreloginDeterministicFakeParams(t *testing.T) {
	e := newEnv(t, nil)
	email := uniqueEmail(t)
	var first, second struct {
		KDF kdf `json:"kdf"`
	}
	e.call(http.MethodPost, "/v1/auth/prelogin", "", map[string]string{"email": email}, http.StatusOK, &first)
	e.call(http.MethodPost, "/v1/auth/prelogin", "", map[string]string{"email": " " + strings.ToUpper(email)}, http.StatusOK, &second)
	want := service.FakeKDF(e.cfg.EnumSecret, email)
	if first.KDF != second.KDF || first.KDF.Salt != want.Salt {
		t.Fatalf("未注册邮箱应返回确定性假参数: %+v vs %+v", first.KDF, second.KDF)
	}
	if first.KDF.Algorithm != "argon2id" || first.KDF.MemoryKiB != 65536 || first.KDF.Iterations != 3 || first.KDF.Parallelism != 4 {
		t.Fatalf("假参数应为默认值: %+v", first.KDF)
	}
	var other struct {
		KDF kdf `json:"kdf"`
	}
	e.call(http.MethodPost, "/v1/auth/prelogin", "", map[string]string{"email": uniqueEmail(t)}, http.StatusOK, &other)
	if other.KDF.Salt == first.KDF.Salt {
		t.Fatalf("不同邮箱的假盐应不同")
	}

	u := e.register(uniqueEmail(t))
	var registered struct {
		KDF kdf `json:"kdf"`
	}
	e.call(http.MethodPost, "/v1/auth/prelogin", "", map[string]string{"email": u.email}, http.StatusOK, &registered)
	if registered.KDF != u.kdf {
		t.Fatalf("已注册邮箱应返回注册时的 KDF: %+v vs %+v", registered.KDF, u.kdf)
	}
}

func TestRegisterValidationAndClosed(t *testing.T) {
	e := newEnv(t, nil)
	base := func() map[string]any {
		return map[string]any{
			"email": uniqueEmail(t), "kdf": newKDF(t), "authKey": b64(randBytes(t, 32)),
			"encryptedAccountKey": b64(randBytes(t, 61)), "recoveryAuthKey": b64(randBytes(t, 32)),
			"recoveryEncryptedAccountKey": b64(randBytes(t, 61)), "device": device("x"),
		}
	}
	weak := newKDF(t)
	weak.MemoryKiB = 19455
	for name, mutate := range map[string]func(map[string]any){
		"弱 KDF":       func(m map[string]any) { m["kdf"] = weak },
		"authKey 长度错": func(m map[string]any) { m["authKey"] = b64(randBytes(t, 31)) },
		"带填充 base64":  func(m map[string]any) { m["encryptedAccountKey"] = "AAAA=" },
		"缺设备":         func(m map[string]any) { delete(m, "device") },
		"邮箱非法":        func(m map[string]any) { m["email"] = "no-at-sign" },
	} {
		body := base()
		mutate(body)
		r := e.do(http.MethodPost, "/v1/auth/register", "", body)
		if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "invalid_request") {
			t.Errorf("%s: 应 400 invalid_request,实际 %d %s", name, r.status, r.body)
		}
	}

	closed := newEnv(t, func(c *config.Config) { c.RegistrationOpen = false })
	closed.expectError(http.MethodPost, "/v1/auth/register", "", base(), http.StatusForbidden, "registration_closed")
}

func TestLoginRateLimitPerEmail(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	wrong := map[string]any{"email": u.email, "authKey": b64(randBytes(t, 32)), "device": device("x")}
	for i := 0; i < 10; i++ {
		e.expectError(http.MethodPost, "/v1/auth/login", "", wrong, http.StatusUnauthorized, "unauthorized")
	}
	r := e.do(http.MethodPost, "/v1/auth/login", "", wrong)
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
		t.Fatalf("同一邮箱第 11 次登录应 429 并带 Retry-After,实际 %d", r.status)
	}
	// 正确口令也被限流(限流先于口令校验)。
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(u.authKey), "device": device("x"),
	}, http.StatusTooManyRequests, "rate_limited")
}

func TestDeviceListAndRevocation(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	a := u.session
	b := e.login(u, "设备 B", nil)

	var list struct {
		Devices []service.Device `json:"devices"`
	}
	e.call(http.MethodGet, "/v1/devices", a.AccessToken, nil, http.StatusOK, &list)
	if len(list.Devices) != 2 {
		t.Fatalf("应有 2 台设备,实际 %d", len(list.Devices))
	}
	for _, d := range list.Devices {
		if (d.ID == a.DeviceID) != d.Current || d.Platform != "macos" || d.CreatedAt == "" || d.LastSeenAt == "" {
			t.Fatalf("设备项不符: %+v", d)
		}
	}

	e.call(http.MethodDelete, "/v1/devices/"+b.DeviceID, a.AccessToken, nil, http.StatusNoContent, nil)
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": b.RefreshToken}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodGet, "/v1/account", b.AccessToken, nil, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodDelete, "/v1/devices/"+b.DeviceID, a.AccessToken, nil, http.StatusNotFound, "not_found")
	e.call(http.MethodGet, "/v1/devices", a.AccessToken, nil, http.StatusOK, &list)
	if len(list.Devices) != 1 || list.Devices[0].ID != a.DeviceID {
		t.Fatalf("吊销后只剩当前设备: %+v", list.Devices)
	}

	// 不能吊销他人的设备。
	other := e.register(uniqueEmail(t))
	e.expectError(http.MethodDelete, "/v1/devices/"+other.session.DeviceID, a.AccessToken, nil, http.StatusNotFound, "not_found")
	e.call(http.MethodGet, "/v1/account", other.session.AccessToken, nil, http.StatusOK, nil)
}

func TestPasswordChangeRevokesOtherDevices(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	a := u.session
	b := e.login(u, "设备 B", nil)

	newKey := randBytes(t, 32)
	nextKDF := newKDF(t)
	body := map[string]any{"authKey": b64(randBytes(t, 32)), "newKdf": nextKDF, "newAuthKey": b64(newKey), "newEncryptedAccountKey": b64(randBytes(t, 61))}
	e.expectError(http.MethodPost, "/v1/account/password", a.AccessToken, body, http.StatusUnauthorized, "unauthorized")
	body["authKey"] = b64(u.authKey)
	e.call(http.MethodPost, "/v1/account/password", a.AccessToken, body, http.StatusNoContent, nil)

	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": b.RefreshToken}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodGet, "/v1/account", b.AccessToken, nil, http.StatusUnauthorized, "unauthorized")
	if r := e.refresh(a.RefreshToken); r.status != http.StatusOK {
		t.Fatalf("改密的当前设备应保持登录: %d %s", r.status, r.body)
	}

	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(u.authKey), "device": device("x"),
	}, http.StatusUnauthorized, "unauthorized")
	u.authKey = newKey
	s := e.login(u, "设备 C", nil)
	if s.KDF != nextKDF || s.EncryptedAccountKey != body["newEncryptedAccountKey"] {
		t.Fatalf("新会话应带新的 KDF 与 encryptedAccountKey")
	}
}

func TestRecoveryFlow(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	enableTOTP(t, e, u.session.AccessToken)

	e.expectError(http.MethodPost, "/v1/auth/recover/begin", "", map[string]string{
		"email": u.email, "recoveryAuthKey": b64(randBytes(t, 32)),
	}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodPost, "/v1/auth/recover/begin", "", map[string]string{
		"email": uniqueEmail(t), "recoveryAuthKey": b64(u.recoveryKey),
	}, http.StatusUnauthorized, "unauthorized")

	var begin service.RecoveryStart
	e.call(http.MethodPost, "/v1/auth/recover/begin", "", map[string]string{
		"email": u.email, "recoveryAuthKey": b64(u.recoveryKey),
	}, http.StatusOK, &begin)
	if begin.RecoveryEncryptedAccountKey == "" || begin.RecoveryToken == "" {
		t.Fatalf("recover/begin 响应不全: %+v", begin)
	}

	newKey := randBytes(t, 32)
	finish := map[string]any{
		"recoveryToken": begin.RecoveryToken, "kdf": newKDF(t), "authKey": b64(newKey),
		"encryptedAccountKey": b64(randBytes(t, 61)), "device": device("恢复后的设备"),
	}
	var s session
	e.call(http.MethodPost, "/v1/auth/recover/finish", "", finish, http.StatusOK, &s)
	if s.UserID != u.session.UserID || s.AccessToken == "" {
		t.Fatalf("恢复后应得到同一账号的会话")
	}
	// 恢复令牌一次性。
	e.expectError(http.MethodPost, "/v1/auth/recover/finish", "", finish, http.StatusUnauthorized, "unauthorized")
	// 旧设备全部吊销。
	e.expectError(http.MethodPost, "/v1/auth/refresh", "", map[string]string{"refreshToken": u.session.RefreshToken}, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodGet, "/v1/account", u.session.AccessToken, nil, http.StatusUnauthorized, "unauthorized")
	// 二次验证已关闭,新口令无需验证码即可登录;旧口令失效。
	var acc service.Account
	e.call(http.MethodGet, "/v1/account", s.AccessToken, nil, http.StatusOK, &acc)
	if acc.TOTPEnabled {
		t.Fatalf("恢复后应关闭二次验证")
	}
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(u.authKey), "device": device("x"),
	}, http.StatusUnauthorized, "unauthorized")
	u.authKey = newKey
	e.login(u, "新设备", nil)

	// 恢复码本身不变:可以再次发起恢复。
	e.call(http.MethodPost, "/v1/auth/recover/begin", "", map[string]string{
		"email": u.email, "recoveryAuthKey": b64(u.recoveryKey),
	}, http.StatusOK, nil)

	// 过期的恢复令牌无效。
	var again service.RecoveryStart
	e.call(http.MethodPost, "/v1/auth/recover/begin", "", map[string]string{
		"email": u.email, "recoveryAuthKey": b64(u.recoveryKey),
	}, http.StatusOK, &again)
	e.exec(`UPDATE recovery_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, auth.Digest(again.RecoveryToken))
	finish["recoveryToken"] = again.RecoveryToken
	e.expectError(http.MethodPost, "/v1/auth/recover/finish", "", finish, http.StatusUnauthorized, "unauthorized")
}

// enableTOTP 为账号开启二次验证,返回密钥。
func enableTOTP(t *testing.T, e *env, token string) []byte {
	t.Helper()
	var setup service.TOTPSetup
	e.call(http.MethodPost, "/v1/account/totp/setup", token, nil, http.StatusOK, &setup)
	secret, err := auth.DecodeTOTPSecret(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	e.call(http.MethodPost, "/v1/account/totp/enable", token, map[string]string{"code": auth.TOTPCode(secret, time.Now())}, http.StatusNoContent, nil)
	return secret
}

func TestTOTPFlow(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	token := u.session.AccessToken

	var setup service.TOTPSetup
	e.call(http.MethodPost, "/v1/account/totp/setup", token, nil, http.StatusOK, &setup)
	if !strings.HasPrefix(setup.OtpauthURL, "otpauth://totp/Typoza:") || !strings.Contains(setup.OtpauthURL, "secret="+setup.Secret) || !strings.HasSuffix(setup.OtpauthURL, "&issuer=Typoza") {
		t.Fatalf("otpauth URL 不符合协议: %s", setup.OtpauthURL)
	}
	// 未启用前可重复 setup,旧密钥作废。
	var setup2 service.TOTPSetup
	e.call(http.MethodPost, "/v1/account/totp/setup", token, nil, http.StatusOK, &setup2)
	if setup2.Secret == setup.Secret {
		t.Fatalf("重复 setup 应生成新密钥")
	}
	secret, err := auth.DecodeTOTPSecret(setup2.Secret)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := auth.DecodeTOTPSecret(setup.Secret)

	t0 := time.Now()
	codeNow := auth.TOTPCode(secret, t0)
	codeNext := auth.TOTPCode(secret, t0.Add(auth.TOTPPeriod*time.Second))

	if oldCode := auth.TOTPCode(old, t0); oldCode != codeNow {
		e.expectError(http.MethodPost, "/v1/account/totp/enable", token, map[string]string{"code": oldCode}, http.StatusUnauthorized, "totp_invalid")
	}
	e.call(http.MethodPost, "/v1/account/totp/enable", token, map[string]string{"code": codeNow}, http.StatusNoContent, nil)
	e.expectError(http.MethodPost, "/v1/account/totp/setup", token, nil, http.StatusBadRequest, "invalid_request")
	// 服务端只存加密后的密钥。
	if n := e.queryInt(`SELECT count(*) FROM users WHERE totp_secret_enc IS NOT NULL AND position($1::bytea IN totp_secret_enc) = 0`, secret); n != 1 {
		t.Fatalf("应有一条已加密的 TOTP 密钥且不含明文")
	}

	creds := map[string]any{"email": u.email, "authKey": b64(u.authKey), "device": device("x")}
	e.expectError(http.MethodPost, "/v1/auth/login", "", creds, http.StatusUnauthorized, "totp_required")
	// 错误口令时不提示是否需要二次验证。
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{
		"email": u.email, "authKey": b64(randBytes(t, 32)), "device": device("x"), "totpCode": codeNow,
	}, http.StatusUnauthorized, "unauthorized")
	creds["totpCode"] = codeNow // enable 已用掉这一步长
	e.expectError(http.MethodPost, "/v1/auth/login", "", creds, http.StatusUnauthorized, "totp_invalid")
	creds["totpCode"] = codeNext
	e.call(http.MethodPost, "/v1/auth/login", "", creds, http.StatusOK, nil)
	e.expectError(http.MethodPost, "/v1/auth/login", "", creds, http.StatusUnauthorized, "totp_invalid")

	// 关闭:需要一个尚未用过的步长;测试里把已用步长拨回,避免等待 30 秒。
	e.exec(`UPDATE users SET totp_last_step = 0 WHERE id = $1`, u.session.UserID)
	e.expectError(http.MethodPost, "/v1/account/totp/disable", token, map[string]string{"code": "000000x"}, http.StatusUnauthorized, "totp_invalid")
	e.call(http.MethodPost, "/v1/account/totp/disable", token, map[string]string{"code": codeNow}, http.StatusNoContent, nil)
	delete(creds, "totpCode")
	e.call(http.MethodPost, "/v1/auth/login", "", creds, http.StatusOK, nil)

}
