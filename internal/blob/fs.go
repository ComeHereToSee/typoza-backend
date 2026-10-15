package blob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// FS 把对象存为本地文件。所有文件操作经由 os.Root,目录外的路径(含符号链接逃逸)在系统层面就被拒绝。
type FS struct {
	root *os.Root
}

// NewFS 打开(必要时创建)目录 dir。
func NewFS(dir string) (*FS, error) {
	if dir == "" {
		return nil, errors.New("本地对象存储目录为空")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建对象存储目录 %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("打开对象存储目录 %s: %w", dir, err)
	}
	return &FS{root: root}, nil
}

// Close 释放目录句柄。
func (s *FS) Close() error {
	return s.root.Close()
}

// Put 先写同目录临时文件、fsync、再 rename,保证读者要么看不到对象,要么看到完整对象。
func (s *FS) Put(ctx context.Context, key string, r io.Reader, size int64) (err error) {
	if !ValidKey(key) {
		return fmt.Errorf("非法对象键 %q", key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := path.Dir(key)
	if dir != "." {
		if err := s.root.MkdirAll(filepath.FromSlash(dir), 0o750); err != nil {
			return fmt.Errorf("创建目录 %s: %w", dir, err)
		}
	}
	tmp := filepath.FromSlash(path.Join(dir, ".tmp-"+randomHex(8)))
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			if rmErr := s.root.Remove(tmp); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("清理临时文件: %w", rmErr))
			}
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, size+1))
	if err != nil {
		return fmt.Errorf("写入对象 %s: %w", key, err)
	}
	if n != size {
		return fmt.Errorf("写入对象 %s: 期望 %d 字节,实际读到 %d 字节", key, size, n)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("同步对象 %s: %w", key, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("关闭对象 %s: %w", key, err)
	}
	if err = s.root.Rename(tmp, filepath.FromSlash(key)); err != nil {
		return fmt.Errorf("落盘对象 %s: %w", key, err)
	}
	// rename 之后同步目录,断电时目录项也不会丢。
	if err = s.syncDir(dir); err != nil {
		return err
	}
	return nil
}

func (s *FS) syncDir(dir string) error {
	d, err := s.root.Open(filepath.FromSlash(dir))
	if err != nil {
		return fmt.Errorf("打开目录 %s: %w", dir, err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("同步目录 %s: %w", dir, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("关闭目录 %s: %w", dir, closeErr)
	}
	return nil
}

// Get 打开对象。
func (s *FS) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if !ValidKey(key) {
		return nil, 0, fmt.Errorf("非法对象键 %q", key)
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	f, err := s.root.Open(filepath.FromSlash(key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("打开对象 %s: %w", key, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("读取对象 %s 元数据: %w", key, err)
	}
	return f, st.Size(), nil
}

// Delete 删除对象,不存在视为成功。
func (s *FS) Delete(ctx context.Context, key string) error {
	if !ValidKey(key) {
		return fmt.Errorf("非法对象键 %q", key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.root.Remove(filepath.FromSlash(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("删除对象 %s: %w", key, err)
	}
	return nil
}

// Exists 判断对象是否存在。
func (s *FS) Exists(ctx context.Context, key string) (bool, error) {
	if !ValidKey(key) {
		return false, fmt.Errorf("非法对象键 %q", key)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := s.root.Stat(filepath.FromSlash(key))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("查询对象 %s: %w", key, err)
}

// Ping 确认根目录仍可访问。
func (s *FS) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := s.root.Stat("."); err != nil {
		return fmt.Errorf("对象存储目录不可用: %w", err)
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("blob: 读取系统随机数失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}
