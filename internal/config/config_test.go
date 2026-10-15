package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func key(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

func baseEnv() map[string]string {
	return map[string]string{
		"TYPOZA_DATABASE_URL":    "postgres://u:p@localhost/db",
		"TYPOZA_BLOB_DRIVER":     "fs",
		"TYPOZA_BLOB_FS_DIR":     "/data/blobs",
		"TYPOZA_JWT_PRIVATE_KEY": key(1),
		"TYPOZA_DATA_KEY":        key(2),
		"TYPOZA_ENUM_SECRET":     key(3),
	}
}

func load(env map[string]string) (Config, error) {
	return Load(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
}

func TestDefaults(t *testing.T) {
	cfg, err := load(baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.MetricsListen != "" {
		t.Fatalf("监听默认值不符: %q %q", cfg.Listen, cfg.MetricsListen)
	}
	if !cfg.RegistrationOpen || cfg.QuotaBytes != 10<<30 || cfg.LogLevel != slog.LevelInfo || cfg.TracingEnabled {
		t.Fatalf("默认值不符: %+v", cfg.LogValue())
	}
	if cfg.Limits != DefaultLimits() || cfg.Limits.IPPerMinute != 30 || cfg.Limits.EmailPerMinute != 10 || cfg.Limits.AccountPerMinute != 1200 {
		t.Fatalf("限流默认值应与协议 §6 一致: %+v", cfg.Limits)
	}
	r := cfg.Retention
	if r.MaxVersions != 50 || r.VersionMaxAge != 90*24*time.Hour || r.TrashTTL != 30*24*time.Hour || r.ChunkGrace != 24*time.Hour || r.Interval != time.Hour {
		t.Fatalf("保留默认值应与协议 §5 一致: %+v", r)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 1
	}
	if !cfg.JWTPrivateKey.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatalf("JWT 私钥应由 32 字节种子派生")
	}
	if cfg.JWTKeyID == "" || cfg.JWTKeyID != DefaultKeyID(cfg.JWTPrivateKey) {
		t.Fatalf("未设置 kid 时应由公钥指纹派生")
	}
}

func TestMissingRequiredListsAll(t *testing.T) {
	_, err := load(map[string]string{"TYPOZA_BLOB_DRIVER": "s3"})
	if err == nil {
		t.Fatal("缺必填项应报错")
	}
	for _, name := range []string{
		"TYPOZA_DATABASE_URL", "TYPOZA_JWT_PRIVATE_KEY", "TYPOZA_DATA_KEY", "TYPOZA_ENUM_SECRET",
		"TYPOZA_S3_ENDPOINT", "TYPOZA_S3_BUCKET", "TYPOZA_S3_ACCESS_KEY", "TYPOZA_S3_SECRET_KEY",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("错误信息应指明缺少 %s: %v", name, err)
		}
	}
}

func TestInvalidValues(t *testing.T) {
	cases := map[string]string{
		"TYPOZA_DATA_KEY":           base64.StdEncoding.EncodeToString([]byte("short")),
		"TYPOZA_ENUM_SECRET":        "!!!不是 base64!!!",
		"TYPOZA_REGISTRATION":       "maybe",
		"TYPOZA_QUOTA_BYTES":        "-1",
		"TYPOZA_TRUSTED_PROXIES":    "10.0.0.0/8,not-an-ip",
		"TYPOZA_LOG_LEVEL":          "loud",
		"TYPOZA_BLOB_DRIVER":        "ftp",
		"TYPOZA_RETENTION_INTERVAL": "soon",
	}
	for name, value := range cases {
		env := baseEnv()
		env[name] = value
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s=%q 应报错并指明变量名,实际 %v", name, value, err)
		}
	}
}

func TestSecretsNotInErrorsOrLogValue(t *testing.T) {
	env := baseEnv()
	secret := strings.Repeat("A", 40) // 合法 base64 但长度不对
	env["TYPOZA_DATA_KEY"] = secret
	_, err := load(env)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("错误信息不得回显密钥: %v", err)
	}
	cfg, err := load(baseEnv())
	if err != nil {
		t.Fatal(err)
	}
	logged := cfg.LogValue().String()
	for _, s := range []string{key(1), key(2), key(3), "u:p@"} {
		if strings.Contains(logged, s) {
			t.Fatalf("LogValue 不得包含密钥或数据库口令: %s", logged)
		}
	}
}

func TestOverridesAndParsing(t *testing.T) {
	env := baseEnv()
	env["TYPOZA_REGISTRATION"] = "closed"
	env["TYPOZA_QUOTA_BYTES"] = "1048576"
	env["TYPOZA_TRUSTED_PROXIES"] = "10.0.0.0/8, 192.168.1.7 ,::1"
	env["TYPOZA_LOG_LEVEL"] = "debug"
	env["TYPOZA_JWT_KEY_ID"] = "k1"
	env["TYPOZA_DATA_KEY"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // URL 字母表无填充也接受
	env["TYPOZA_RATE_IP_PER_MINUTE"] = "0"
	env["TYPOZA_RETENTION_INTERVAL"] = "0"
	env["TYPOZA_RETENTION_VERSION_DAYS"] = "7"
	env["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://otel:4318"
	cfg, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RegistrationOpen || cfg.QuotaBytes != 1<<20 || cfg.LogLevel != slog.LevelDebug || cfg.JWTKeyID != "k1" || !cfg.TracingEnabled {
		t.Fatalf("覆盖值未生效: %+v", cfg.LogValue())
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.7/32"),
		netip.MustParsePrefix("::1/128"),
	}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("受信代理解析不符: %v", cfg.TrustedProxies)
	}
	for i := range want {
		if cfg.TrustedProxies[i] != want[i] {
			t.Fatalf("受信代理[%d] = %v,期望 %v", i, cfg.TrustedProxies[i], want[i])
		}
	}
	if cfg.Limits.IPPerMinute != 0 || cfg.Retention.Interval != 0 || cfg.Retention.VersionMaxAge != 7*24*time.Hour {
		t.Fatalf("限流/保留覆盖未生效: %+v %+v", cfg.Limits, cfg.Retention)
	}
}

func TestS3Config(t *testing.T) {
	env := baseEnv()
	env["TYPOZA_BLOB_DRIVER"] = "s3"
	env["TYPOZA_S3_ENDPOINT"] = "minio:9000"
	env["TYPOZA_S3_BUCKET"] = "typoza"
	env["TYPOZA_S3_ACCESS_KEY"] = "ak"
	env["TYPOZA_S3_SECRET_KEY"] = "sk"
	env["TYPOZA_S3_USE_TLS"] = "false"
	cfg, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Blob.Driver != BlobDriverS3 || cfg.Blob.S3UseTLS || cfg.Blob.S3Endpoint != "minio:9000" {
		t.Fatalf("S3 配置不符: %+v", cfg.Blob)
	}
	env["TYPOZA_S3_ENDPOINT"] = "https://minio:9000"
	if _, err := load(env); err == nil {
		t.Fatalf("endpoint 带协议应报错")
	}
}
