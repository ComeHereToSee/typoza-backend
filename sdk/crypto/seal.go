package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

// 封装格式(协议 §2.2):0x01 ‖ nonce(12) ‖ ciphertext ‖ tag(16)。
const (
	sealVersion byte = 0x01
	nonceSize        = 12
	tagSize          = 16
	// SealOverhead 是封装结果比明文多出的字节数。
	SealOverhead = 1 + nonceSize + tagSize
)

// AAD 串(协议 §2.2)。改动 = 改公共契约。
const (
	aadAccountKey      = "typoza/v1/account-key"
	aadVaultNamePrefix = "typoza/v1/vault-name|"
	aadManifestPrefix  = "typoza/v1/manifest|"
	aadChunkPrefix     = "typoza/v1/chunk|"
)

var (
	// ErrFormat 表示封装数据的结构不对(长度不足、版本号未知等)。
	ErrFormat = errors.New("crypto: 封装格式错误")
	// ErrDecrypt 表示认证解密失败:密钥错误、AAD 不符或数据被篡改。
	ErrDecrypt = errors.New("crypto: 解密失败(密钥错误、AAD 不符或数据被篡改)")
)

// seal 按协议封装:AES-256-GCM,随机 12 字节 nonce。
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceSize, SealOverhead+len(plaintext))
	out[0] = sealVersion
	_, _ = rand.Read(out[1 : 1+nonceSize]) // Go 1.24+ 保证不返回错误
	return gcm.Seal(out, out[1:1+nonceSize], plaintext, aad), nil
}

// open 解开 seal 的输出。版本号不是 0x01 时直接报错,不做任何猜测(协议 §2.2)。
func open(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < SealOverhead {
		return nil, fmt.Errorf("%w: 长度 %d 小于最小 %d", ErrFormat, len(sealed), SealOverhead)
	}
	if sealed[0] != sealVersion {
		return nil, fmt.Errorf("%w: 未知格式版本号 0x%02x", ErrFormat, sealed[0])
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, sealed[1:1+nonceSize], sealed[1+nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: 密钥长度 %d,应为 %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 GCM: %w", err)
	}
	return gcm, nil
}

// WrapAccountKey 用 WrapKey 封装 AccountKey,得到 encryptedAccountKey。
func WrapAccountKey(w WrapKey, ak AccountKey) ([]byte, error) {
	return seal(w[:], ak[:], []byte(aadAccountKey))
}

// UnwrapAccountKey 解开 encryptedAccountKey。主密码错误时返回 ErrDecrypt。
func UnwrapAccountKey(w WrapKey, sealed []byte) (AccountKey, error) {
	return unwrapAccountKey(w[:], sealed)
}

// WrapAccountKeyForRecovery 用 RecoveryWrapKey 封装 AccountKey,得到 recoveryEncryptedAccountKey。
func WrapAccountKeyForRecovery(r RecoveryWrapKey, ak AccountKey) ([]byte, error) {
	return seal(r[:], ak[:], []byte(aadAccountKey))
}

// UnwrapAccountKeyForRecovery 解开 recoveryEncryptedAccountKey。
func UnwrapAccountKeyForRecovery(r RecoveryWrapKey, sealed []byte) (AccountKey, error) {
	return unwrapAccountKey(r[:], sealed)
}

func unwrapAccountKey(key, sealed []byte) (AccountKey, error) {
	pt, err := open(key, sealed, []byte(aadAccountKey))
	if err != nil {
		return AccountKey{}, fmt.Errorf("crypto: 解开账户密钥: %w", err)
	}
	if len(pt) != KeySize {
		return AccountKey{}, fmt.Errorf("%w: 账户密钥长度 %d,应为 %d", ErrFormat, len(pt), KeySize)
	}
	var ak AccountKey
	copy(ak[:], pt)
	return ak, nil
}

// EncryptVaultName 加密库名,AAD 绑定 vaultId,防止服务器把 A 库的名字换给 B 库。
func EncryptVaultName(m MetaKey, vaultID, name string) ([]byte, error) {
	if !uuid.Valid(vaultID) {
		return nil, fmt.Errorf("crypto: vaultId %q 不是小写 UUID", vaultID)
	}
	if !utf8.ValidString(name) {
		return nil, errors.New("crypto: 库名不是合法 UTF-8")
	}
	return seal(m[:], []byte(name), []byte(aadVaultNamePrefix+vaultID))
}

// DecryptVaultName 解密库名。
func DecryptVaultName(m MetaKey, vaultID string, sealed []byte) (string, error) {
	pt, err := open(m[:], sealed, []byte(aadVaultNamePrefix+vaultID))
	if err != nil {
		return "", fmt.Errorf("crypto: 解密库 %s 的名称: %w", vaultID, err)
	}
	if !utf8.Valid(pt) {
		return "", fmt.Errorf("%w: 库名不是合法 UTF-8", ErrFormat)
	}
	return string(pt), nil
}
