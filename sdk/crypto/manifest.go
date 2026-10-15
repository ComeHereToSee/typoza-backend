package crypto

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/internal/relpath"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

// Manifest 是文件清单明文(协议 §2.4)。
type Manifest struct {
	// Path 相对库根目录,'/' 分隔,NFC 规范化。
	Path string
	// Size 文件明文字节数;墓碑为 0。
	Size int64
	// MTime 文件修改时间,序列化为 UTC 毫秒精度 RFC 3339。
	MTime time.Time
	// ContentHash 文件内容摘要;墓碑为空串。
	ContentHash string
	// Chunks 有序块 ID 列表;墓碑为空。
	Chunks []string
	// Deleted 为 true 表示删除墓碑。
	Deleted bool
}

// manifestJSON 固定协议字段名与顺序;mtime 用字符串以控制精度与时区。
type manifestJSON struct {
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	MTime       string   `json:"mtime"`
	ContentHash string   `json:"contentHash"`
	Chunks      []string `json:"chunks"`
	Deleted     bool     `json:"deleted"`
}

// timeLayout 对应协议示例 "2026-10-16T01:02:03.123Z"(UTC、毫秒)。
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// FormatTime 把时间格式化为协议使用的 UTC 毫秒 RFC 3339 字符串。
func FormatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// ParseTime 解析 RFC 3339 时间(接受任意小数位与时区)。
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("crypto: 解析时间 %q: %w", s, err)
	}
	return t, nil
}

// Validate 校验清单自洽:路径规范、墓碑字段为空、块数与大小匹配。
func (m Manifest) Validate() error {
	if err := relpath.Validate(m.Path); err != nil {
		return fmt.Errorf("crypto: 清单路径: %w", err)
	}
	if m.Deleted {
		if m.Size != 0 || len(m.Chunks) != 0 || m.ContentHash != "" {
			return fmt.Errorf("%w: 墓碑清单 %q 的 size/chunks/contentHash 必须为空", ErrFormat, m.Path)
		}
		return nil
	}
	if m.Size < 0 {
		return fmt.Errorf("%w: 清单 %q 的 size 为负数", ErrFormat, m.Path)
	}
	if !ValidContentHash(m.ContentHash) {
		return fmt.Errorf("%w: 清单 %q 的 contentHash 格式错误", ErrFormat, m.Path)
	}
	want := (m.Size + ChunkSize - 1) / ChunkSize
	if int64(len(m.Chunks)) != want {
		return fmt.Errorf("%w: 清单 %q 大小 %d 应有 %d 块,实际 %d 块", ErrFormat, m.Path, m.Size, want, len(m.Chunks))
	}
	for _, id := range m.Chunks {
		if !ValidChunkID(id) {
			return fmt.Errorf("%w: 清单 %q 含非法 chunkId %q", ErrFormat, m.Path, id)
		}
	}
	return nil
}

func manifestAAD(vaultID, fileID string, version int64) []byte {
	return []byte(aadManifestPrefix + vaultID + "|" + fileID + "|" + strconv.FormatInt(version, 10))
}

func checkManifestIDs(vaultID, fileID string, version int64) error {
	if !uuid.Valid(vaultID) {
		return fmt.Errorf("crypto: vaultId %q 不是小写 UUID", vaultID)
	}
	if !uuid.Valid(fileID) {
		return fmt.Errorf("crypto: fileId %q 不是小写 UUID", fileID)
	}
	if version < 1 {
		return fmt.Errorf("crypto: 清单版本号 %d 必须 ≥ 1", version)
	}
	return nil
}

// EncryptManifest 加密清单。AAD 绑定 vaultId、fileId 与版本号,服务器无法把清单挪到别的文件或版本。
func EncryptManifest(k MetaKey, vaultID, fileID string, version int64, m Manifest) ([]byte, error) {
	if err := checkManifestIDs(vaultID, fileID, version); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	chunks := m.Chunks
	if chunks == nil {
		chunks = []string{} // 协议要求墓碑与空文件是 [] 而不是 null
	}
	pt, err := json.Marshal(manifestJSON{
		Path:        m.Path,
		Size:        m.Size,
		MTime:       FormatTime(m.MTime),
		ContentHash: m.ContentHash,
		Chunks:      chunks,
		Deleted:     m.Deleted,
	})
	if err != nil {
		return nil, fmt.Errorf("crypto: 序列化清单: %w", err)
	}
	return seal(k[:], pt, manifestAAD(vaultID, fileID, version))
}

// DecryptManifest 解密并校验清单。
func DecryptManifest(k MetaKey, vaultID, fileID string, version int64, sealed []byte) (Manifest, error) {
	if err := checkManifestIDs(vaultID, fileID, version); err != nil {
		return Manifest{}, err
	}
	pt, err := open(k[:], sealed, manifestAAD(vaultID, fileID, version))
	if err != nil {
		return Manifest{}, fmt.Errorf("crypto: 解密文件 %s 版本 %d 的清单: %w", fileID, version, err)
	}
	var j manifestJSON
	if err := json.Unmarshal(pt, &j); err != nil {
		return Manifest{}, fmt.Errorf("%w: 解析文件 %s 的清单 JSON: %v", ErrFormat, fileID, err)
	}
	mt, err := ParseTime(j.MTime)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: 文件 %s 的清单 mtime: %v", ErrFormat, fileID, err)
	}
	m := Manifest{
		Path:        j.Path,
		Size:        j.Size,
		MTime:       mt,
		ContentHash: j.ContentHash,
		Chunks:      j.Chunks,
		Deleted:     j.Deleted,
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
