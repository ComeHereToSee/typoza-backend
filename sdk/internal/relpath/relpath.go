// Package relpath 处理库内相对路径。
//
// 协议(sync-protocol §2.4)要求清单里的 path:相对库根目录、'/' 分隔、NFC 规范化、
// 不以 '/' 开头、不含 '.'、'..' 段。远端清单里的路径来自网络,落盘前必须过这里,
// 否则恶意或有 bug 的清单可以把文件写到库目录之外。
package relpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ErrInvalid 表示路径不符合协议要求。
var ErrInvalid = errors.New("relpath: 非法的库内相对路径")

// Clean 把 p 规范化为协议形式(NFC)并校验,返回规范化后的路径。
func Clean(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: 空路径", ErrInvalid)
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("%w: %q 不是合法 UTF-8", ErrInvalid, p)
	}
	if strings.IndexByte(p, 0) >= 0 {
		return "", fmt.Errorf("%w: %q 含 NUL 字符", ErrInvalid, p)
	}
	p = norm.NFC.String(p)
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%w: %q 以 / 开头", ErrInvalid, p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: %q 含空段或 ./.. 段", ErrInvalid, p)
		}
	}
	return p, nil
}

// Validate 要求 p 已经是规范形式(Clean(p) == p)。用于校验远端清单里的路径:
// 发送方本应提交规范路径,不规范说明清单有问题,直接拒绝而不是替它纠正。
func Validate(p string) error {
	c, err := Clean(p)
	if err != nil {
		return err
	}
	if c != p {
		return fmt.Errorf("%w: %q 未做 NFC 规范化", ErrInvalid, p)
	}
	return nil
}

// FromOS 把 root 之下的本机路径转换为库内相对路径。
func FromOS(root, abs string) (string, error) {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", fmt.Errorf("relpath: 计算 %q 相对 %q 的路径: %w", abs, root, err)
	}
	return Clean(filepath.ToSlash(rel))
}

// ToOS 把规范的库内相对路径转换为 root 之下的本机路径。
func ToOS(root, rel string) (string, error) {
	if err := Validate(rel); err != nil {
		return "", err
	}
	return filepath.Join(root, filepath.FromSlash(rel)), nil
}

// Dir 返回库内相对路径的父目录;位于库根时返回空串。
func Dir(rel string) string {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return ""
	}
	return rel[:i]
}

// Base 返回库内相对路径的最后一段。
func Base(rel string) string {
	return rel[strings.LastIndexByte(rel, '/')+1:]
}
