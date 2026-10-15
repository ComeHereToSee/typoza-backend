package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ComeHereToSee/typoza-backend/internal/ids"
)

func TestHasherDeterministicAndVerify(t *testing.T) {
	h := NewHasher(2)
	ctx := context.Background()
	secret := bytes.Repeat([]byte{7}, 32)
	salt := NewSalt()
	if len(salt) != SaltLen {
		t.Fatalf("盐长度 %d,期望 %d", len(salt), SaltLen)
	}
	a, err := h.Hash(ctx, secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Hash(ctx, secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatalf("同输入应得到相同 32 字节哈希")
	}
	ok, err := h.Verify(ctx, secret, salt, a)
	if err != nil || !ok {
		t.Fatalf("正确口令校验失败: ok=%v err=%v", ok, err)
	}
	wrong := bytes.Repeat([]byte{8}, 32)
	ok, err = h.Verify(ctx, wrong, salt, a)
	if err != nil || ok {
		t.Fatalf("错误口令不应通过: ok=%v err=%v", ok, err)
	}
	other, err := h.Hash(ctx, secret, NewSalt())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, other) {
		t.Fatalf("不同盐应得到不同哈希")
	}
}

func TestHasherRespectsContext(t *testing.T) {
	h := NewHasher(1)
	h.sem <- struct{}{} // 占满槽位
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, []byte("x"), NewSalt()); !errors.Is(err, context.Canceled) {
		t.Fatalf("槽位占满且 ctx 已取消时应返回 context.Canceled,实际 %v", err)
	}
}

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWTRoundTripAndClaims(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	uid, did := ids.New(), ids.New()
	tok, err := s.Issue(uid, did, now)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, gotDID, err := s.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("校验刚签发的令牌失败: %v", err)
	}
	if gotUID != uid || gotDID != did {
		t.Fatalf("载荷不符: %s %s", gotUID, gotDID)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT 应有三段")
	}
	var header map[string]any
	mustDecodeSegment(t, parts[0], &header)
	if header["alg"] != "EdDSA" || header["typ"] != "JWT" || header["kid"] != "test-kid" {
		t.Fatalf("JWT 头不符合协议: %v", header)
	}
	var payload map[string]any
	mustDecodeSegment(t, parts[1], &payload)
	if payload["iss"] != "typoza" || payload["aud"] != "typoza-api" || payload["sub"] != uid || payload["did"] != did {
		t.Fatalf("JWT 载荷不符合协议: %v", payload)
	}
	exp, _ := payload["exp"].(float64)
	iat, _ := payload["iat"].(float64)
	if exp-iat != AccessTTL.Seconds() {
		t.Fatalf("有效期应为 900 秒,实际 %v", exp-iat)
	}
}

func TestJWTExpired(t *testing.T) {
	s := newTestSigner(t)
	issued := time.Now().Add(-AccessTTL - time.Minute)
	tok, err := s.Issue(ids.New(), ids.New(), issued)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(tok, time.Now()); !errors.Is(err, ErrAccessExpired) {
		t.Fatalf("过期令牌应返回 ErrAccessExpired,实际 %v", err)
	}
}

func TestJWTTampered(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	tok, err := s.Issue(ids.New(), ids.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	var payload map[string]any
	mustDecodeSegment(t, parts[1], &payload)
	payload["sub"] = ids.New()
	raw, _ := json.Marshal(payload)
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	forged := strings.Join(parts, ".")
	if _, _, err := s.Verify(forged, now); !errors.Is(err, ErrAccessInvalid) {
		t.Fatalf("篡改载荷应返回 ErrAccessInvalid,实际 %v", err)
	}

	// 用另一把私钥签名(kid 相同)也必须被拒绝。
	other := newTestSigner(t)
	other.kid = s.kid
	tok2, err := other.Issue(ids.New(), ids.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(tok2, now); !errors.Is(err, ErrAccessInvalid) {
		t.Fatalf("他人私钥签名应返回 ErrAccessInvalid,实际 %v", err)
	}

	// kid 不符。
	other2 := newTestSigner(t)
	other2.priv, other2.pub = s.priv, s.pub
	other2.kid = "another"
	tok3, err := other2.Issue(ids.New(), ids.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(tok3, now); !errors.Is(err, ErrAccessInvalid) {
		t.Fatalf("kid 不符应返回 ErrAccessInvalid,实际 %v", err)
	}
}

func TestJWTRejectsOtherAlgorithms(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	claims := &accessClaims{
		Issuer: TokenIssuer, Audience: TokenAudience, Subject: ids.New(), DeviceID: ids.New(),
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	}
	// 经典算法混淆:用公钥字节当 HMAC 密钥签 HS256。
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hs.Header["kid"] = s.kid
	hsTok, err := hs.SignedString([]byte(s.pub))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(hsTok, now); !errors.Is(err, ErrAccessInvalid) {
		t.Fatalf("HS256 令牌应被拒绝,实际 %v", err)
	}
	// alg=none。
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	none.Header["kid"] = s.kid
	noneTok, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(noneTok, now); !errors.Is(err, ErrAccessInvalid) {
		t.Fatalf("alg=none 令牌应被拒绝,实际 %v", err)
	}
}

func TestJWTWrongAudienceOrIssuer(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	for _, c := range []*accessClaims{
		{Issuer: "evil", Audience: TokenAudience},
		{Issuer: TokenIssuer, Audience: "other-api"},
	} {
		c.Subject, c.DeviceID = ids.New(), ids.New()
		c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(time.Minute))
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		tok.Header["kid"] = s.kid
		signed, err := tok.SignedString(s.priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Verify(signed, now); !errors.Is(err, ErrAccessInvalid) {
			t.Fatalf("iss=%s aud=%s 应被拒绝,实际 %v", c.Issuer, c.Audience, err)
		}
	}
}

func mustDecodeSegment(t *testing.T, seg string, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func TestOpaqueTokens(t *testing.T) {
	plain, digest := NewOpaque(RefreshPrefix)
	if !strings.HasPrefix(plain, "tzr_") || len(plain) != len("tzr_")+43 {
		t.Fatalf("刷新令牌格式不符: %q", plain)
	}
	if !ValidOpaque(RefreshPrefix, plain) {
		t.Fatalf("自己生成的令牌应合法")
	}
	sum := sha256.Sum256([]byte(plain))
	if !bytes.Equal(digest, sum[:]) || !bytes.Equal(Digest(plain), digest) {
		t.Fatalf("摘要应为 SHA-256(明文)")
	}
	for _, bad := range []string{"", "tzr_", "tzv_" + plain[4:], plain + "A", "tzr_" + strings.Repeat("=", 43)} {
		if ValidOpaque(RefreshPrefix, bad) {
			t.Fatalf("非法令牌被接受: %q", bad)
		}
	}
	other, _ := NewOpaque(RefreshPrefix)
	if other == plain {
		t.Fatalf("两次生成的令牌不应相同")
	}
}

// RFC 6238 附录 B 的 SHA-1 测试向量(8 位)。
func TestHOTPRFC6238Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		step := TOTPStep(time.Unix(c.unix, 0))
		if got := HOTP(seed, stepCounter(step), 8); got != c.want {
			t.Errorf("T=%d: 得到 %s,期望 %s", c.unix, got, c.want)
		}
	}
}

// RFC 4226 附录 D 的 HOTP 向量(6 位),验证截断与补零。
func TestHOTPRFC4226Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := HOTP(seed, uint64(i), 6); got != w {
			t.Errorf("counter=%d: 得到 %s,期望 %s", i, got, w)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_015, 0)
	cur := TOTPStep(now)

	code := TOTPCode(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || step != cur {
		t.Fatalf("当前步长验证码应通过: ok=%v step=%d", ok, step)
	}
	// 同一步长重放:lastStep 已是 cur,必须拒绝。
	if _, ok := VerifyTOTP(secret, code, now, cur); ok {
		t.Fatalf("同一步长的验证码不得重复使用")
	}
	// ±1 步容差。
	prev := TOTPCode(secret, now.Add(-TOTPPeriod*time.Second))
	if s, ok := VerifyTOTP(secret, prev, now, 0); !ok || s != cur-1 {
		t.Fatalf("上一步长应在容差内: ok=%v s=%d", ok, s)
	}
	next := TOTPCode(secret, now.Add(TOTPPeriod*time.Second))
	if s, ok := VerifyTOTP(secret, next, now, 0); !ok || s != cur+1 {
		t.Fatalf("下一步长应在容差内: ok=%v s=%d", ok, s)
	}
	// 超出 ±1 步。
	old := TOTPCode(secret, now.Add(-2*TOTPPeriod*time.Second))
	if old != code && old != prev && old != next {
		if _, ok := VerifyTOTP(secret, old, now, 0); ok {
			t.Fatalf("两步之前的验证码不应通过")
		}
	}
	// 格式错误。
	for _, bad := range []string{"", "12345", "1234567", "12a456"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Fatalf("格式错误的验证码 %q 不应通过", bad)
		}
	}
}

func TestTOTPSecretEncodingAndURL(t *testing.T) {
	secret := NewTOTPSecret()
	enc := EncodeTOTPSecret(secret)
	if len(enc) != 32 || strings.ContainsAny(enc, "=abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("Base32 应为 32 个大写字符且无填充: %q", enc)
	}
	dec, err := DecodeTOTPSecret(enc)
	if err != nil || !bytes.Equal(dec, secret) {
		t.Fatalf("Base32 往返失败: %v", err)
	}
	u := TOTPURL("a@b.c", secret)
	want := "otpauth://totp/Typoza:a@b.c?secret=" + enc + "&issuer=Typoza"
	if u != want {
		t.Fatalf("otpauth URL 不符:\n得到 %s\n期望 %s", u, want)
	}
}

func TestSecretBox(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	box, err := NewSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("user-1")
	sealed := box.Seal([]byte("hello"), aad)
	pt, err := box.Open(sealed, aad)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("往返失败: %v", err)
	}
	if _, err := box.Open(sealed, []byte("user-2")); err == nil {
		t.Fatalf("AAD 不符应解密失败")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := box.Open(sealed, aad); err == nil {
		t.Fatalf("篡改密文应解密失败")
	}
	if _, err := NewSecretBox([]byte("short")); err == nil {
		t.Fatalf("密钥长度不对应报错")
	}
}
