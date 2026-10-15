package httpapi

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/ids"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// 边界校验:格式不对的输入在这里挡掉,业务层可以假定输入格式正确。
const (
	keyLen              = 32      // authKey / recoveryAuthKey 字节数(协议 §4.1)
	maxEmailLen         = 254     // RFC 5321 地址上限
	maxWrappedKeyBytes  = 1024    // encryptedAccountKey 解码后上限(实际约 61 字节)
	maxVaultNameBytes   = 4096    // encryptedName 解码后上限
	maxManifestBytes    = 4 << 20 // 加密清单解码后上限
	maxDeviceNameBytes  = 200
	maxPlatformBytes    = 32
	maxCheckIDs         = 1000 // 协议 §4.3
	maxCommitChunks     = 100000
	defaultChangesLimit = 500  // 协议 §4.4
	maxChangesLimit     = 1000 // 协议 §4.4
)

func invalid(format string, args ...any) error {
	return apierr.InvalidRequest(fmt.Sprintf(format, args...))
}

// normalizeEmail 按协议 trim + 小写,并做最基本的形状检查(不做 MX 等投递性校验)。
func normalizeEmail(s string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(s))
	if e == "" || len(e) > maxEmailLen || !utf8.ValidString(e) {
		return "", invalid("email 格式不正确")
	}
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", invalid("email 格式不正确")
	}
	for _, r := range e {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", invalid("email 格式不正确")
		}
	}
	return e, nil
}

// decodeB64 严格按 base64url 无填充解码(协议 §2),长度在 [minLen, maxLen] 内。
func decodeB64(field, s string, minLen, maxLen int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, invalid("%s 应为 base64url(无填充)", field)
	}
	if len(b) < minLen || len(b) > maxLen {
		if minLen == maxLen {
			return nil, invalid("%s 解码后应为 %d 字节", field, minLen)
		}
		return nil, invalid("%s 解码后长度应在 %d~%d 字节之间", field, minLen, maxLen)
	}
	return b, nil
}

func decodeKey(field, s string) ([]byte, error) {
	return decodeB64(field, s, keyLen, keyLen)
}

// checkB64Text 校验以 base64url 文本原样入库的密文字段。
func checkB64Text(field, s string, maxLen int) error {
	_, err := decodeB64(field, s, 1, maxLen)
	return err
}

func checkKDF(field string, k *service.KDF) error {
	if k == nil {
		return invalid("缺少 %s", field)
	}
	if err := k.Validate(); err != nil {
		return apierr.InvalidRequest(err.Error())
	}
	return nil
}

// checkDevice 校验并整理设备信息。
func checkDevice(d *service.DeviceInfo) (service.DeviceInfo, error) {
	if d == nil {
		return service.DeviceInfo{}, invalid("缺少 device")
	}
	name := strings.TrimSpace(d.Name)
	platform := strings.TrimSpace(d.Platform)
	if name == "" || len(name) > maxDeviceNameBytes || !printable(name) {
		return service.DeviceInfo{}, invalid("device.name 应为 1~%d 字节的可打印文本", maxDeviceNameBytes)
	}
	if platform == "" || len(platform) > maxPlatformBytes || !printable(platform) {
		return service.DeviceInfo{}, invalid("device.platform 应为 1~%d 字节的可打印文本", maxPlatformBytes)
	}
	return service.DeviceInfo{Name: name, Platform: platform}, nil
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func checkUUID(field, s string) error {
	if !ids.Valid(s) {
		return invalid("%s 应为小写带连字符的 UUID", field)
	}
	return nil
}

// validChunkID 判断是否为 64 位小写十六进制(协议 §4.3)。
func validChunkID(s string) bool {
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

func checkChunkIDs(field string, list []string) error {
	for _, id := range list {
		if !validChunkID(id) {
			return invalid("%s 中的块 ID 应为 64 位小写十六进制", field)
		}
	}
	return nil
}
