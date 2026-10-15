// Package ids 生成与校验 UUID(RFC 9562 v4)。
//
// 协议规定 vaultId、fileId 等是「小写带连字符」的 UUID 字符串,并且会进入客户端加密的 AAD,
// 所以服务端只接受规范小写形式:同一个 UUID 的大小写变体若被 PostgreSQL uuid 类型归一化,
// 会让客户端 AAD 与服务端记录对不上。
package ids

import "crypto/rand"

const hexDigits = "0123456789abcdef"

// New 返回随机 v4 UUID 的规范小写字符串。
func New() string {
	var b [16]byte
	// crypto/rand.Read 自 Go 1.24 起不会返回错误(失败时直接终止进程),这里仍检查以防语义变化。
	if _, err := rand.Read(b[:]); err != nil {
		panic("ids: 读取系统随机数失败: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // 版本 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 9562 变体
	var out [36]byte
	j := 0
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j] = hexDigits[c>>4]
		out[j+1] = hexDigits[c&0x0f]
		j += 2
	}
	return string(out[:])
}

// Valid 判断 s 是否为规范小写的 8-4-4-4-12 形式 UUID(不限版本)。
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
