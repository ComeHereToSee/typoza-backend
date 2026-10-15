package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// 不透明令牌:前缀 + base64url(32 随机字节)。服务器只存 SHA-256 摘要,数据库泄露也拿不到可用令牌。
const (
	// RefreshPrefix 是刷新令牌前缀(同步协议 §3.1)。
	RefreshPrefix = "tzr_"
	// RecoveryPrefix 是恢复流程令牌前缀;协议只规定它是不透明串,前缀是服务端自定,便于日志与排查时区分。
	RecoveryPrefix = "tzv_"

	opaqueRandomLen = 32

	// RefreshTTL 刷新令牌有效期 30 天,每次刷新轮换后重新计时(同步协议 §3.1)。
	RefreshTTL = 30 * 24 * time.Hour
	// RecoveryTTL 恢复令牌 10 分钟有效、一次性(同步协议 §4.1)。
	RecoveryTTL = 10 * time.Minute
)

// NewOpaque 生成带前缀的随机令牌,返回明文与摘要。
func NewOpaque(prefix string) (plain string, digest []byte) {
	plain = prefix + base64.RawURLEncoding.EncodeToString(randomBytes(opaqueRandomLen))
	return plain, Digest(plain)
}

// Digest 返回令牌明文的 SHA-256 摘要(入库与查找都用它)。
func Digest(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// ValidOpaque 检查令牌格式:指定前缀 + 32 字节的无填充 base64url。格式不对的直接拒绝,不必查库。
func ValidOpaque(prefix, plain string) bool {
	rest, ok := strings.CutPrefix(plain, prefix)
	if !ok {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil && len(b) == opaqueRandomLen
}
