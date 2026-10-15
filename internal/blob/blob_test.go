package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/ids"
)

func TestValidKey(t *testing.T) {
	good := []string{"a", "chunks/u/abc-0123", "x.y_z-1/b"}
	bad := []string{"", "/a", "a/", "a//b", "../a", "a/../b", "./a", ".tmp-1", "a/.hidden", "A", "a b", "a\\b", strings.Repeat("a", 513)}
	for _, k := range good {
		if !ValidKey(k) {
			t.Errorf("%q 应合法", k)
		}
	}
	for _, k := range bad {
		if ValidKey(k) {
			t.Errorf("%q 应非法", k)
		}
	}
}

// storeContract 是两种实现共用的行为测试。
func storeContract(t *testing.T, s Store) {
	ctx := context.Background()
	key := "chunks/" + ids.New() + "/obj-1"
	data := bytes.Repeat([]byte("密文"), 1000)

	if ok, err := s.Exists(ctx, key); err != nil || ok {
		t.Fatalf("写入前不应存在: ok=%v err=%v", ok, err)
	}
	if _, _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的对象应返回 ErrNotFound,实际 %v", err)
	}
	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err := s.Exists(ctx, key); err != nil || !ok {
		t.Fatalf("写入后应存在: ok=%v err=%v", ok, err)
	}
	rc, size, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || size != int64(len(data)) || !bytes.Equal(got, data) {
		t.Fatalf("读回内容不符: size=%d err=%v", size, err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("重复删除应幂等: %v", err)
	}
	if ok, err := s.Exists(ctx, key); err != nil || ok {
		t.Fatalf("删除后不应存在: ok=%v err=%v", ok, err)
	}
	if err := s.Put(ctx, "../escape", bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatalf("非法键应被拒绝")
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestFSContract(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	storeContract(t, s)
}

func TestFSSizeMismatchLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	for _, size := range []int64{3, 100} { // 实际 5 字节:声明过小、过大都要失败
		if err := s.Put(ctx, "d/k", strings.NewReader("hello"), size); err == nil {
			t.Fatalf("声明 %d 字节、实际 5 字节时应失败", size)
		}
	}
	if ok, _ := s.Exists(ctx, "d/k"); ok {
		t.Fatalf("失败的写入不应留下对象")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "d"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("失败的写入不应留下临时文件: %v", entries)
	}
}

func TestFSOverwriteIsAtomic(t *testing.T) {
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if err := s.Put(ctx, "k", strings.NewReader("one"), 3); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "k", strings.NewReader("two!"), 4); err != nil {
		t.Fatal(err)
	}
	rc, size, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if size != 4 || string(b) != "two!" {
		t.Fatalf("覆盖写后应读到新内容: %q", b)
	}
}

func TestFSRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	s, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Put(context.Background(), "link/x", strings.NewReader("x"), 1); err == nil {
		t.Fatalf("经符号链接写到根目录之外应被拒绝")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Fatalf("根目录之外出现了文件")
	}
}

// TestS3Contract 需要 MinIO:TYPOZA_TEST_S3_ENDPOINT / _ACCESS_KEY / _SECRET_KEY(http)。
func TestS3Contract(t *testing.T) {
	endpoint := os.Getenv("TYPOZA_TEST_S3_ENDPOINT")
	ak := os.Getenv("TYPOZA_TEST_S3_ACCESS_KEY")
	sk := os.Getenv("TYPOZA_TEST_S3_SECRET_KEY")
	if endpoint == "" || ak == "" || sk == "" {
		t.Skip("未设置 TYPOZA_TEST_S3_*,跳过 S3 集成测试")
	}
	cfg := config.Blob{
		Driver:      config.BlobDriverS3,
		S3Endpoint:  endpoint,
		S3Bucket:    "typoza-blob-test-" + ids.New()[:8],
		S3AccessKey: ak,
		S3SecretKey: sk,
		S3UseTLS:    false,
	}
	s, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
	// 再次 Open 同一个桶(模拟第二个实例启动)不应报错。
	if _, err := Open(context.Background(), cfg); err != nil {
		t.Fatalf("桶已存在时再次打开应成功: %v", err)
	}
}
