package auth

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 与主流验证器 App 规定 TOTP 用 HMAC-SHA1;HMAC 场景下 SHA-1 碰撞不构成威胁
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP 参数(同步协议 §4.1:RFC 6238,SHA-1,6 位,30 秒步长,允许 ±1 步)。
const (
	TOTPDigits    = 6
	TOTPPeriod    = 30 // 秒
	totpSkewSteps = 1
	// RFC 4226 §4 建议密钥至少 128 位,推荐 160 位(与 SHA-1 输出等长)。
	totpSecretLen = 20
	totpIssuer    = "Typoza"
)

// totpEncoding 是验证器 App 通用的 Base32(大写、无填充)。
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret 生成 20 字节随机 TOTP 密钥。
func NewTOTPSecret() []byte {
	return randomBytes(totpSecretLen)
}

// EncodeTOTPSecret 把密钥编码为 Base32(展示给用户、写进 otpauth URL)。
func EncodeTOTPSecret(secret []byte) string {
	return totpEncoding.EncodeToString(secret)
}

// DecodeTOTPSecret 解析 Base32 密钥(测试与客户端模拟用)。
func DecodeTOTPSecret(s string) ([]byte, error) {
	b, err := totpEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("解析 TOTP 密钥: %w", err)
	}
	return b, nil
}

// TOTPURL 生成验证器 App 扫码用的 otpauth URL(格式见同步协议 §4.1)。
func TOTPURL(email string, secret []byte) string {
	return "otpauth://totp/" + totpIssuer + ":" + url.PathEscape(email) +
		"?secret=" + EncodeTOTPSecret(secret) + "&issuer=" + totpIssuer
}

// TOTPStep 返回 t 所在的时间步序号(RFC 6238 的 T)。
func TOTPStep(t time.Time) int64 {
	return t.Unix() / TOTPPeriod
}

// HOTP 计算 RFC 4226 一次性口令(动态截断后取 digits 位十进制,左侧补零)。
func HOTP(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key) // #nosec G401 -- RFC 6238 规定的 HMAC-SHA1
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// TOTPCode 返回 t 时刻的 6 位验证码。
func TOTPCode(secret []byte, t time.Time) string {
	return HOTP(secret, stepCounter(TOTPStep(t)), TOTPDigits)
}

// VerifyTOTP 在当前步长 ±1 内查找与 code 匹配且大于 lastStep 的步长。
// 只接受比上次成功步长更新的步长,保证同一步长的验证码只能用一次(协议 §4.1)。
// 返回匹配的步长;调用方必须把它原子地写回 lastStep,才算真正消费了这个验证码。
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if !validTOTPCode(code) {
		return 0, false
	}
	cur := TOTPStep(now)
	for s := cur - totpSkewSteps; s <= cur+totpSkewSteps; s++ {
		if s <= lastStep || s < 0 {
			continue
		}
		want := HOTP(secret, stepCounter(s), TOTPDigits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

func validTOTPCode(code string) bool {
	if len(code) != TOTPDigits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// stepCounter 把步长转成 HOTP 计数器。调用方保证 s ≥ 0(Unix 时间之后的步长)。
func stepCounter(s int64) uint64 {
	if s < 0 {
		return 0
	}
	return uint64(s) // #nosec G115 -- 上一行已排除负数
}
