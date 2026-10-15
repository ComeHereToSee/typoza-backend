// Package blob 是数据块密文的对象存储抽象,有 S3 兼容与本地磁盘两种实现。
//
// 存进来的都是客户端加密后的密文,存储层不解析内容。
package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ComeHereToSee/typoza-backend/internal/config"
)

// ErrNotFound 表示对象不存在。
var ErrNotFound = errors.New("对象不存在")

// Store 是对象存储接口。key 由服务端生成,格式见 ValidKey。
type Store interface {
	// Put 写入恰好 size 字节;读到的字节数不符时返回错误且不留下对象。
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get 返回对象内容与大小;不存在时返回 ErrNotFound。调用方负责关闭。
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	// Delete 删除对象;对象本就不存在视为成功(删除是幂等的)。
	Delete(ctx context.Context, key string) error
	// Exists 判断对象是否存在。
	Exists(ctx context.Context, key string) (bool, error)
	// Ping 检查存储可用(就绪探针)。
	Ping(ctx context.Context) error
}

// Open 按配置创建存储;S3 驱动会在桶不存在时创建它。
func Open(ctx context.Context, cfg config.Blob) (Store, error) {
	switch cfg.Driver {
	case config.BlobDriverS3:
		return NewS3(ctx, cfg)
	case config.BlobDriverFS:
		return NewFS(cfg.FSDir)
	default:
		return nil, fmt.Errorf("未知对象存储驱动 %q", cfg.Driver)
	}
}

// ValidKey 校验对象键:以 / 分隔的若干段,每段只含小写字母、数字、'.'、'_'、'-' 且不以 '.' 开头。
// 这样天然排除了 "."、".." 与以点开头的临时文件名,磁盘实现不会被路径穿越。
func ValidKey(key string) bool {
	if key == "" || len(key) > 512 {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg[0] == '.' {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}
