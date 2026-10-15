package blob

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ComeHereToSee/typoza-backend/internal/config"
)

// S3 是 S3 兼容对象存储(AWS S3、MinIO、R2 等)。
type S3 struct {
	client *minio.Client
	bucket string
}

// NewS3 创建客户端并确保桶存在。多实例同时启动可能并发建桶,BucketAlreadyOwnedByYou 视为成功。
func NewS3(ctx context.Context, cfg config.Blob) (*S3, error) {
	client, err := minio.New(cfg.S3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: cfg.S3UseTLS,
		Region: cfg.S3Region,
	})
	if err != nil {
		return nil, fmt.Errorf("创建 S3 客户端(%s): %w", cfg.S3Endpoint, err)
	}
	s := &S3{client: client, bucket: cfg.S3Bucket}
	exists, err := client.BucketExists(ctx, cfg.S3Bucket)
	if err != nil {
		return nil, fmt.Errorf("检查桶 %s: %w", cfg.S3Bucket, err)
	}
	if !exists {
		err = client.MakeBucket(ctx, cfg.S3Bucket, minio.MakeBucketOptions{Region: cfg.S3Region})
		if err != nil && minio.ToErrorResponse(err).Code != minio.BucketAlreadyOwnedByYou {
			return nil, fmt.Errorf("创建桶 %s: %w", cfg.S3Bucket, err)
		}
	}
	return s, nil
}

// Put 上传对象。
func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if !ValidKey(key) {
		return fmt.Errorf("非法对象键 %q", key)
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("上传对象 %s: %w", key, err)
	}
	return nil
}

// Get 下载对象。minio 的 GetObject 是惰性的,先 Stat 才能区分「不存在」与其它错误。
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if !ValidKey(key) {
		return nil, 0, fmt.Errorf("非法对象键 %q", key)
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("下载对象 %s: %w", key, err)
	}
	info, err := obj.Stat()
	if err != nil {
		closeErr := obj.Close()
		if isNoSuchKey(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, errors.Join(fmt.Errorf("读取对象 %s 元数据: %w", key, err), closeErr)
	}
	return obj, info.Size, nil
}

// Delete 删除对象;S3 删除本身是幂等的。
func (s *S3) Delete(ctx context.Context, key string) error {
	if !ValidKey(key) {
		return fmt.Errorf("非法对象键 %q", key)
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil && !isNoSuchKey(err) {
		return fmt.Errorf("删除对象 %s: %w", key, err)
	}
	return nil
}

// Exists 判断对象是否存在。
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	if !ValidKey(key) {
		return false, fmt.Errorf("非法对象键 %q", key)
	}
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if isNoSuchKey(err) {
		return false, nil
	}
	return false, fmt.Errorf("查询对象 %s: %w", key, err)
}

// Ping 确认桶可访问。
func (s *S3) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("访问桶 %s: %w", s.bucket, err)
	}
	if !ok {
		return fmt.Errorf("桶 %s 不存在", s.bucket)
	}
	return nil
}

func isNoSuchKey(err error) bool {
	return minio.ToErrorResponse(err).Code == minio.NoSuchKey
}
