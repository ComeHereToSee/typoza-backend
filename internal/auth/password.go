// Package auth 提供服务端的密码学原语:口令二次哈希、访问令牌、刷新与恢复令牌、TOTP、静态数据加密。
//
// 这里只有纯计算,不碰数据库;流程编排在 service 包。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// 服务端口令哈希参数(同步协议 §2:内存 19 MiB、迭代 2、并行 1、输出 32 字节、每用户 16 字节随机盐)。
// 客户端发来的 authKey 已经是主密码派生出的 32 字节密钥,服务器再做一次 Argon2id 才入库,
// 这样数据库泄露后无法直接拿 authKey 冒充登录。
const (
	argonTime      = 2
	argonMemoryKiB = 19 * 1024
	argonThreads   = 1
	argonKeyLen    = 32

	// SaltLen 是服务端哈希盐长度。
	SaltLen = 16
)

// Hasher 计算 Argon2id。每次计算占 19 MiB 内存,用信号量限制并发,防止登录洪峰把内存打满。
type Hasher struct {
	sem chan struct{}
}

// NewHasher 创建并发上限为 concurrency 的哈希器(至少 1)。
func NewHasher(concurrency int) *Hasher {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Hasher{sem: make(chan struct{}, concurrency)}
}

// Hash 计算 Argon2id(secret, salt);排队等待时尊重 ctx 取消。
func (h *Hasher) Hash(ctx context.Context, secret, salt []byte) ([]byte, error) {
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("等待口令哈希槽位: %w", ctx.Err())
	}
	defer func() { <-h.sem }()
	return argon2.IDKey(secret, salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen), nil
}

// Verify 用常量时间比较 Argon2id(secret, salt) 与 want。
func (h *Hasher) Verify(ctx context.Context, secret, salt, want []byte) (bool, error) {
	got, err := h.Hash(ctx, secret, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NewSalt 生成 16 字节随机盐。
func NewSalt() []byte {
	return randomBytes(SaltLen)
}

// randomBytes 读取 n 字节系统随机数。crypto/rand.Read 自 Go 1.24 起失败即终止进程,这里的检查只是防御。
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: 读取系统随机数失败: " + err.Error())
	}
	return b
}
