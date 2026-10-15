// Package testutil 为集成测试与 e2e 组装隔离的服务配置。
//
// 依赖的环境变量(CI 已配置):
//   - TYPOZA_TEST_DATABASE_URL:PostgreSQL 17 连接串;缺失时调用方测试被跳过。
//   - TYPOZA_TEST_S3_ENDPOINT / TYPOZA_TEST_S3_ACCESS_KEY / TYPOZA_TEST_S3_SECRET_KEY:MinIO(http);
//     三者齐全时用 S3 驱动,否则退回本地磁盘驱动(t.TempDir)。
package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ComeHereToSee/typoza-backend/internal/config"
)

// NewTestConfig 返回一份与其它测试完全隔离的配置:
//   - 数据库:新建随机 schema,并通过连接串的 search_path 让服务只在该 schema 内建表;t.Cleanup 时删除。
//   - 对象存储:S3 用随机桶名(服务启动时自动建桶),否则用 t.TempDir()。
//   - 密钥:JWT、数据密钥、枚举密钥全部随机生成。
//   - 限流:与生产默认值相同,测试可在返回值上自行调整 cfg.Limits。
//   - 后台回收:关闭定时任务(Retention.Interval = 0),需要时调用 (*app.App).RunRetention。
//
// 未设置 TYPOZA_TEST_DATABASE_URL 时调用 t.Skip。
func NewTestConfig(t testing.TB) config.Config {
	t.Helper()
	baseURL := os.Getenv("TYPOZA_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("未设置 TYPOZA_TEST_DATABASE_URL,跳过需要 PostgreSQL 的测试")
	}
	suffix := randomHex(t, 6)
	schema := "t_" + suffix
	dbURL := createSchema(t, baseURL, schema)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 JWT 密钥: %v", err)
	}
	retention := config.DefaultRetention()
	retention.Interval = 0

	cfg := config.Config{
		Listen:           "127.0.0.1:0",
		DatabaseURL:      dbURL,
		JWTPrivateKey:    priv,
		JWTKeyID:         config.DefaultKeyID(priv),
		DataKey:          randomBytes(t, 32),
		EnumSecret:       randomBytes(t, 32),
		RegistrationOpen: true,
		QuotaBytes:       config.DefaultQuotaBytes(),
		Limits:           config.DefaultLimits(),
		Retention:        retention,
	}

	endpoint := os.Getenv("TYPOZA_TEST_S3_ENDPOINT")
	ak := os.Getenv("TYPOZA_TEST_S3_ACCESS_KEY")
	sk := os.Getenv("TYPOZA_TEST_S3_SECRET_KEY")
	if endpoint != "" && ak != "" && sk != "" {
		cfg.Blob = config.Blob{
			Driver:      config.BlobDriverS3,
			S3Endpoint:  endpoint,
			S3Bucket:    "typoza-test-" + suffix,
			S3AccessKey: ak,
			S3SecretKey: sk,
			S3UseTLS:    false,
		}
	} else {
		cfg.Blob = config.Blob{Driver: config.BlobDriverFS, FSDir: t.TempDir()}
	}
	return cfg
}

// createSchema 建 schema 并返回带 search_path 的连接串;注册清理函数在测试结束时删除它。
func createSchema(t testing.TB, baseURL, schema string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("连接测试数据库: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("创建测试 schema: %v", err)
	}
	t.Cleanup(func() { dropSchema(t, baseURL, schema) })

	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("TYPOZA_TEST_DATABASE_URL 需为 postgres:// URL 形式")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// dropSchema 删除测试 schema。清理失败只记日志:不影响被测行为,CI 数据库是一次性的。
func dropSchema(t testing.TB, baseURL, schema string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Logf("清理测试 schema %s:连接失败: %v", schema, err)
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Logf("清理测试 schema %s 失败: %v", schema, err)
	}
}

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("读取随机数: %v", err)
	}
	return b
}

func randomHex(t testing.TB, n int) string {
	return hex.EncodeToString(randomBytes(t, n))
}
