// Package crypto 实现 Typoza 同步协议 v1(docs/sync-protocol.md §2)的客户端密码学:
// 主密码派生、密钥层级、封装格式、数据块、文件清单、库名与恢复码。
//
// 所有密钥都用具名的 32 字节数组类型表示,编译期就能挡住「拿 metaKey 去解块」这类传错。
package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// KeySize 是协议中所有对称密钥与派生密钥的字节长度。
const KeySize = 32

// SaltSize 是 Argon2id 盐的字节长度(协议 §2)。
const SaltSize = 16

// HKDF info 串(协议 §2.1)。改动 = 改公共契约。
const (
	infoAuth         = "typoza/v1/auth"
	infoWrap         = "typoza/v1/wrap"
	infoMeta         = "typoza/v1/meta"
	infoChunk        = "typoza/v1/chunk"
	infoChunkID      = "typoza/v1/chunk-id"
	infoRecoveryWrap = "typoza/v1/recovery-wrap"
	infoRecoveryAuth = "typoza/v1/recovery-auth"
	infoChunkPrefix  = "typoza/v1/chunk/"
)

type (
	// MasterKey 由主密码经 Argon2id 派生,只用于再派生 AuthKey 与 WrapKey,永不出本机。
	MasterKey [KeySize]byte
	// AuthKey 发给服务器用于登录(服务器再做一次 Argon2id 才入库)。
	AuthKey [KeySize]byte
	// WrapKey 加密 AccountKey,永不出本机。
	WrapKey [KeySize]byte
	// AccountKey 是全账号唯一的数据主密钥,注册时随机生成。
	AccountKey [KeySize]byte
	// MetaKey 加密文件清单与库名。
	MetaKey [KeySize]byte
	// ChunkKey 是数据块密钥的根,每块再经 HKDF 派生独立密钥。
	ChunkKey [KeySize]byte
	// ChunkIDKey 用于 HMAC 计算块 ID 与文件内容摘要。
	ChunkIDKey [KeySize]byte
	// RecoveryKey 是注册时随机生成、只给用户看一次的恢复密钥。
	RecoveryKey [KeySize]byte
	// RecoveryWrapKey 另包一份 AccountKey,供忘记主密码时恢复。
	RecoveryWrapKey [KeySize]byte
	// RecoveryAuthKey 发给服务器用于证明持有恢复码。
	RecoveryAuthKey [KeySize]byte
)

// Keys 是解锁后的账号数据密钥集合。
type Keys struct {
	Account AccountKey
	Meta    MetaKey
	Chunk   ChunkKey
	ChunkID ChunkIDKey
}

// DeriveKeys 由 AccountKey 派生出全部数据子密钥。
func DeriveKeys(ak AccountKey) *Keys {
	return &Keys{
		Account: ak,
		Meta:    MetaKey(hkdf32(ak[:], infoMeta)),
		Chunk:   ChunkKey(hkdf32(ak[:], infoChunk)),
		ChunkID: ChunkIDKey(hkdf32(ak[:], infoChunkID)),
	}
}

// NewAccountKey 生成随机 AccountKey(注册时调用一次)。
func NewAccountKey() AccountKey {
	var k AccountKey
	_, _ = rand.Read(k[:]) // Go 1.24+ 保证不返回错误
	return k
}

// NewRecoveryKey 生成随机 RecoveryKey(注册时调用一次)。
func NewRecoveryKey() RecoveryKey {
	var k RecoveryKey
	_, _ = rand.Read(k[:])
	return k
}

// AuthKey 派生登录用的 AuthKey。
func (m MasterKey) AuthKey() AuthKey { return AuthKey(hkdf32(m[:], infoAuth)) }

// WrapKey 派生包装 AccountKey 用的 WrapKey。
func (m MasterKey) WrapKey() WrapKey { return WrapKey(hkdf32(m[:], infoWrap)) }

// WrapKey 派生恢复用的包装密钥。
func (r RecoveryKey) WrapKey() RecoveryWrapKey {
	return RecoveryWrapKey(hkdf32(r[:], infoRecoveryWrap))
}

// AuthKey 派生恢复流程发给服务器的认证密钥。
func (r RecoveryKey) AuthKey() RecoveryAuthKey {
	return RecoveryAuthKey(hkdf32(r[:], infoRecoveryAuth))
}

// hkdfSHA256 是 RFC 5869 HKDF-SHA256 的薄封装,单独拎出来便于用 RFC 测试向量做已知答案测试。
func hkdfSHA256(secret, salt []byte, info string, n int) ([]byte, error) {
	out, err := hkdf.Key(sha256.New, secret, salt, info, n)
	if err != nil {
		return nil, fmt.Errorf("crypto: HKDF-SHA256 派生: %w", err)
	}
	return out, nil
}

// hkdf32 按协议用空 salt 派生 32 字节子密钥。
// 输入是 32 字节密钥、输出 32 字节,标准库只会在 FIPS-only 模式下密钥短于 14 字节
// 或输出超过 255*32 字节时报错,这里都不可能触发,所以出错即程序缺陷,直接 panic。
func hkdf32(secret []byte, info string) [KeySize]byte {
	out, err := hkdfSHA256(secret, nil, info, KeySize)
	if err != nil {
		panic(err)
	}
	var k [KeySize]byte
	copy(k[:], out)
	return k
}

// KDF 参数下限(协议 §4.1,服务器同样校验)与客户端自设上限。
// 上限用来防止恶意服务器在 prelogin 下发天价参数把客户端内存打爆;
// 下限同时防止服务器下发弱参数,借 authKey 离线爆破主密码。
const (
	MinMemoryKiB   = 19456
	MinIterations  = 2
	MinParallelism = 1
	MaxParallelism = 16
	maxMemoryKiB   = 1 << 20 // 1 GiB
	maxIterations  = 64
)

// Argon2id 默认参数(协议 §2)。
const (
	DefaultMemoryKiB   = 65536
	DefaultIterations  = 3
	DefaultParallelism = 4
)

// KDFParams 是 Argon2id 的派生参数。
type KDFParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	Salt        []byte
}

// ErrWeakKDF 表示 KDF 参数超出允许范围。
var ErrWeakKDF = errors.New("crypto: KDF 参数超出允许范围")

// DefaultKDF 返回协议默认参数与新的随机盐(注册、改密、恢复时使用)。
func DefaultKDF() KDFParams {
	salt := make([]byte, SaltSize)
	_, _ = rand.Read(salt)
	return KDFParams{
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
		Salt:        salt,
	}
}

// Validate 校验参数在协议下限与客户端上限之间、盐长度为 16 字节。
func (p KDFParams) Validate() error {
	switch {
	case p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("%w: memoryKiB=%d,允许 %d~%d", ErrWeakKDF, p.MemoryKiB, MinMemoryKiB, maxMemoryKiB)
	case p.Iterations < MinIterations || p.Iterations > maxIterations:
		return fmt.Errorf("%w: iterations=%d,允许 %d~%d", ErrWeakKDF, p.Iterations, MinIterations, maxIterations)
	case p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism:
		return fmt.Errorf("%w: parallelism=%d,允许 %d~%d", ErrWeakKDF, p.Parallelism, MinParallelism, MaxParallelism)
	case len(p.Salt) != SaltSize:
		return fmt.Errorf("%w: 盐长度 %d,应为 %d 字节", ErrWeakKDF, len(p.Salt), SaltSize)
	}
	return nil
}

// NormalizePassword 按协议把主密码做 Unicode NFC 规范化后转成字节;
// 同一个密码在不同输入法/系统下可能是组合或分解形式,不规范化会导致换设备登录不上。
func NormalizePassword(password string) []byte {
	return []byte(norm.NFC.String(password))
}

// DeriveMasterKey 校验参数后用 Argon2id 从主密码派生 MasterKey。
func DeriveMasterKey(password string, p KDFParams) (MasterKey, error) {
	if err := p.Validate(); err != nil {
		return MasterKey{}, err
	}
	out := argon2id(NormalizePassword(password), p.Salt, p.Iterations, p.MemoryKiB, p.Parallelism)
	var k MasterKey
	copy(k[:], out)
	return k, nil
}

// argon2id 是 Argon2id(版本 0x13)的薄封装,单独拎出来便于做已知答案测试。
func argon2id(password, salt []byte, iterations, memoryKiB uint32, parallelism uint8) []byte {
	return argon2.IDKey(password, salt, iterations, memoryKiB, parallelism, KeySize)
}
