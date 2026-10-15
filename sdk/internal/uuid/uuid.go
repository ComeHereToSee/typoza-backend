// Package uuid 生成与校验协议使用的小写带连字符 UUID(v4,随机)。
// 只需要这两个功能,不为此引入第三方依赖。
package uuid

import (
	"crypto/rand"
	"encoding/hex"
)

// New 返回一个随机 v4 UUID,形如 xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx(小写)。
func New() string {
	var b [16]byte
	// crypto/rand.Read 自 Go 1.24 起保证填满且不返回错误(失败时进程直接崩溃)。
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// Valid 判断 s 是否为小写带连字符的 UUID 字符串(不限版本)。
func Valid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
