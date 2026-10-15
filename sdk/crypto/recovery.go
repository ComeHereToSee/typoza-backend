package crypto

import (
	"encoding/base32"
	"fmt"
	"strings"
	"unicode"
)

// recoveryEncoding:RFC 4648 Base32 标准字母表 A-Z2-7,无填充(协议 §2.1)。
var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatRecoveryCode 把恢复密钥格式化为展示给用户的恢复码:
// 32 字节 → 52 个 Base32 字符 → 每 4 字符一组用 '-' 连接(13 组)。
func FormatRecoveryCode(k RecoveryKey) string {
	s := recoveryEncoding.EncodeToString(k[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// ParseRecoveryCode 解析用户输入的恢复码:忽略 '-' 与空白,不区分大小写。
func ParseRecoveryCode(code string) (RecoveryKey, error) {
	var b strings.Builder
	for _, r := range code {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	raw, err := recoveryEncoding.DecodeString(b.String())
	if err != nil {
		return RecoveryKey{}, fmt.Errorf("crypto: 恢复码格式错误: %w", err)
	}
	if len(raw) != KeySize {
		return RecoveryKey{}, fmt.Errorf("crypto: 恢复码长度错误:解出 %d 字节,应为 %d", len(raw), KeySize)
	}
	var k RecoveryKey
	copy(k[:], raw)
	return k, nil
}
