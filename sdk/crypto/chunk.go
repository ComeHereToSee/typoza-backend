package crypto

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

// ChunkSize 是数据块定长切分的大小:4 MiB(协议 §2.3),最后一块可以更短。
const ChunkSize = 4 * 1024 * 1024

// MaxSealedChunkSize 是单块密文的上限:flags 1 字节 + 原文最多 ChunkSize + 封装开销。
const MaxSealedChunkSize = ChunkSize + 1 + SealOverhead

// flagDeflate:flags 位 0,payload 经 DEFLATE(raw,无 zlib 头)压缩。
const flagDeflate byte = 1 << 0

const contentHashPrefix = "typoza/v1/file|"

// ErrChunkMismatch 表示解出的块明文与 chunkId 对不上:数据被篡改或服务器调换了块。
var ErrChunkMismatch = errors.New("crypto: 块内容与 chunkId 不符(数据被篡改或被调换)")

// ChunkID 计算块 ID:hex(HMAC-SHA256(chunkIdKey, 块明文))。
func ChunkID(k ChunkIDKey, plain []byte) string {
	mac := hmac.New(sha256.New, k[:])
	mac.Write(plain)
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidChunkID 判断 id 是否为 64 位小写十六进制。
func ValidChunkID(id string) bool {
	return isHex64(id)
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// chunkKey 为单个块派生独立密钥:HKDF(chunkKey, "typoza/v1/chunk/" + chunkId)。
func chunkKey(k ChunkKey, id string) []byte {
	kk := hkdf32(k[:], infoChunkPrefix+id)
	return kk[:]
}

// EncryptChunk 加密一个块。明文首字节是 flags;DEFLATE 压缩后变小才置位压缩,否则存原文。
func EncryptChunk(k ChunkKey, id string, plain []byte) ([]byte, error) {
	if !ValidChunkID(id) {
		return nil, fmt.Errorf("crypto: chunkId %q 不是 64 位小写十六进制", id)
	}
	if len(plain) > ChunkSize {
		return nil, fmt.Errorf("crypto: 块长度 %d 超过上限 %d", len(plain), ChunkSize)
	}
	flags := byte(0)
	payload := plain
	compressed, err := deflate(plain)
	if err != nil {
		return nil, err
	}
	if len(compressed) < len(plain) {
		flags = flagDeflate
		payload = compressed
	}
	buf := make([]byte, 0, 1+len(payload))
	buf = append(buf, flags)
	buf = append(buf, payload...)
	return seal(chunkKey(k, id), buf, []byte(aadChunkPrefix+id))
}

// DecryptChunk 解密一个块:解密 → 按 flags 解压 → 重算 HMAC 必须等于 chunkId(协议 §2.3)。
func DecryptChunk(k ChunkKey, idk ChunkIDKey, id string, sealed []byte) ([]byte, error) {
	if !ValidChunkID(id) {
		return nil, fmt.Errorf("crypto: chunkId %q 不是 64 位小写十六进制", id)
	}
	pt, err := open(chunkKey(k, id), sealed, []byte(aadChunkPrefix+id))
	if err != nil {
		return nil, fmt.Errorf("crypto: 解密块 %s: %w", id, err)
	}
	if len(pt) < 1 {
		return nil, fmt.Errorf("%w: 块 %s 缺少 flags 字节", ErrFormat, id)
	}
	flags, payload := pt[0], pt[1:]
	if flags&^flagDeflate != 0 {
		return nil, fmt.Errorf("%w: 块 %s 含未知 flags 0x%02x", ErrFormat, id, flags)
	}
	plain := payload
	if flags&flagDeflate != 0 {
		plain, err = inflate(payload)
		if err != nil {
			return nil, fmt.Errorf("crypto: 解压块 %s: %w", id, err)
		}
	}
	if len(plain) > ChunkSize {
		return nil, fmt.Errorf("%w: 块 %s 明文长度 %d 超过上限", ErrFormat, id, len(plain))
	}
	if ChunkID(idk, plain) != id {
		return nil, fmt.Errorf("%w: %s", ErrChunkMismatch, id)
	}
	return plain, nil
}

func deflate(p []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("crypto: 初始化 DEFLATE: %w", err)
	}
	if _, err := w.Write(p); err != nil {
		return nil, fmt.Errorf("crypto: DEFLATE 压缩: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("crypto: DEFLATE 压缩: %w", err)
	}
	return buf.Bytes(), nil
}

// inflate 解压 raw DEFLATE;限制输出不超过 ChunkSize,防止解压炸弹。
func inflate(p []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(p))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, ChunkSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > ChunkSize {
		return nil, fmt.Errorf("解压后超过 %d 字节", ChunkSize)
	}
	return out, nil
}

// ContentHasher 流式计算文件内容摘要:hex(HMAC-SHA256(chunkIdKey, "typoza/v1/file|" ‖ 全文件明文))。
type ContentHasher struct {
	mac hash.Hash
}

// NewContentHasher 返回已写入协议前缀的摘要计算器。
func NewContentHasher(k ChunkIDKey) *ContentHasher {
	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte(contentHashPrefix))
	return &ContentHasher{mac: mac}
}

// Write 追加文件内容,永不返回错误。
func (h *ContentHasher) Write(p []byte) (int, error) { return h.mac.Write(p) }

// Sum 返回 64 位小写十六进制摘要。
func (h *ContentHasher) Sum() string { return hex.EncodeToString(h.mac.Sum(nil)) }

// ContentHash 一次性计算整段内容的摘要。
func ContentHash(k ChunkIDKey, data []byte) string {
	h := NewContentHasher(k)
	_, _ = h.Write(data)
	return h.Sum()
}

// ValidContentHash 判断 s 是否为 64 位小写十六进制。
func ValidContentHash(s string) bool {
	return isHex64(s)
}
