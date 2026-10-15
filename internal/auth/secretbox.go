package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// SecretBox 用服务端数据密钥(TYPOZA_DATA_KEY)做 AES-256-GCM 加密,用于 TOTP 密钥等少量服务端机密入库。
// 格式:nonce(12) ‖ 密文 ‖ tag(16)。AAD 由调用方绑定到具体用户,防止把 A 的密文挪给 B 使用。
type SecretBox struct {
	aead cipher.AEAD
}

// NewSecretBox 用 32 字节密钥创建。
func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("数据密钥应为 32 字节,实际 %d 字节", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM: %w", err)
	}
	return &SecretBox{aead: aead}, nil
}

// Seal 加密 plaintext。
func (b *SecretBox) Seal(plaintext, aad []byte) []byte {
	nonce := randomBytes(b.aead.NonceSize())
	return b.aead.Seal(nonce, nonce, plaintext, aad)
}

// Open 解密 Seal 的输出;密文被篡改或 AAD 不符时返回错误。
func (b *SecretBox) Open(sealed, aad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, errors.New("密文长度不足")
	}
	pt, err := b.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, fmt.Errorf("解密服务端机密: %w", err)
	}
	return pt, nil
}
