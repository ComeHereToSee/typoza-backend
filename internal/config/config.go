// Package config 从环境变量组装服务端运行参数。
//
// 所有必填项缺失或格式错误会一次性汇总报出,方便部署时一次改对;
// 密钥类字段只在内存里保存解码后的字节,LogValue 不会输出它们。
package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// 对象存储驱动。
const (
	BlobDriverS3 = "s3"
	BlobDriverFS = "fs"
)

// 密钥字节长度:JWT 种子、数据密钥、枚举密钥都要求 32 字节。
const keyLen = 32

// 默认值(同步协议 §5、§6)。
const (
	defaultListen     = ":8080"
	defaultQuotaBytes = int64(10) << 30 // 10 GiB
)

// Config 是服务端全部运行参数。
type Config struct {
	Listen        string // HTTP 监听地址
	MetricsListen string // 非空时 /metrics 单独监听,主端口不再暴露
	DatabaseURL   string // PostgreSQL 连接串(可带 search_path 等运行时参数)

	Blob Blob

	JWTPrivateKey ed25519.PrivateKey // 访问令牌签名私钥
	JWTKeyID      string             // JWT 头 kid
	DataKey       []byte             // 服务端静态数据密钥(AES-256-GCM 加密 TOTP 密钥)
	EnumSecret    []byte             // prelogin 防探测:未注册邮箱的假盐 = HMAC(EnumSecret, 邮箱)

	RegistrationOpen bool
	QuotaBytes       int64          // 新账号的默认配额
	TrustedProxies   []netip.Prefix // 只信这些来源的 X-Forwarded-For
	LogLevel         slog.Level
	TracingEnabled   bool // 设置了 OTEL_EXPORTER_OTLP_ENDPOINT 才启用 OpenTelemetry

	Limits    Limits
	Retention Retention
}

// Blob 是对象存储配置。
type Blob struct {
	Driver      string // BlobDriverS3 | BlobDriverFS
	FSDir       string
	S3Endpoint  string // host:port,不带协议
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3Region    string
	S3UseTLS    bool
}

// Limits 是限流上限(同步协议 §6),单位:次/分钟;0 表示不限。
type Limits struct {
	IPPerMinute      int // 未认证接口每 IP
	EmailPerMinute   int // 登录与恢复每邮箱
	AccountPerMinute int // 已认证接口每账号
}

// Retention 是保留与回收规则(同步协议 §5)。
type Retention struct {
	Interval      time.Duration // 后台回收任务间隔;0 表示不启动后台任务(测试用,手动调用)
	MaxVersions   int           // 每文件最多保留的历史版本数(含当前版本)
	VersionMaxAge time.Duration // 历史版本最长保留时间(当前版本永远保留)
	TrashTTL      time.Duration // 回收站文件自动永久删除的时长
	ChunkGrace    time.Duration // 未被引用的块在上传多久后才允许回收
}

// DefaultLimits 返回协议规定的默认限流上限。
func DefaultLimits() Limits {
	return Limits{IPPerMinute: 30, EmailPerMinute: 10, AccountPerMinute: 1200}
}

// DefaultRetention 返回协议规定的默认保留规则。
func DefaultRetention() Retention {
	return Retention{
		Interval:      time.Hour,
		MaxVersions:   50,
		VersionMaxAge: 90 * 24 * time.Hour,
		TrashTTL:      30 * 24 * time.Hour,
		ChunkGrace:    24 * time.Hour,
	}
}

// DefaultQuotaBytes 是新账号默认配额(10 GiB)。
func DefaultQuotaBytes() int64 { return defaultQuotaBytes }

// FromEnv 从进程环境变量读取配置。
func FromEnv() (Config, error) {
	return Load(os.LookupEnv)
}

// Load 用给定的查找函数读取配置,便于测试注入。
func Load(lookup func(string) (string, bool)) (Config, error) {
	p := &parser{lookup: lookup}
	cfg := Config{
		Listen:           p.str("TYPOZA_LISTEN", defaultListen),
		MetricsListen:    p.str("TYPOZA_METRICS_LISTEN", ""),
		DatabaseURL:      p.required("TYPOZA_DATABASE_URL"),
		RegistrationOpen: p.registration("TYPOZA_REGISTRATION"),
		QuotaBytes:       p.positiveInt64("TYPOZA_QUOTA_BYTES", defaultQuotaBytes),
		TrustedProxies:   p.prefixes("TYPOZA_TRUSTED_PROXIES"),
		LogLevel:         p.level("TYPOZA_LOG_LEVEL"),
	}
	cfg.TracingEnabled = p.str("OTEL_EXPORTER_OTLP_ENDPOINT", "") != "" || p.str("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "") != ""

	cfg.Blob = p.blob()

	if seed := p.key("TYPOZA_JWT_PRIVATE_KEY"); seed != nil {
		cfg.JWTPrivateKey = ed25519.NewKeyFromSeed(seed)
	}
	cfg.JWTKeyID = p.str("TYPOZA_JWT_KEY_ID", "")
	if cfg.JWTKeyID == "" && cfg.JWTPrivateKey != nil {
		cfg.JWTKeyID = DefaultKeyID(cfg.JWTPrivateKey)
	}
	cfg.DataKey = p.key("TYPOZA_DATA_KEY")
	cfg.EnumSecret = p.key("TYPOZA_ENUM_SECRET")

	def := DefaultLimits()
	cfg.Limits = Limits{
		IPPerMinute:      p.nonNegativeInt("TYPOZA_RATE_IP_PER_MINUTE", def.IPPerMinute),
		EmailPerMinute:   p.nonNegativeInt("TYPOZA_RATE_EMAIL_PER_MINUTE", def.EmailPerMinute),
		AccountPerMinute: p.nonNegativeInt("TYPOZA_RATE_ACCOUNT_PER_MINUTE", def.AccountPerMinute),
	}

	ret := DefaultRetention()
	cfg.Retention = Retention{
		Interval:      p.duration("TYPOZA_RETENTION_INTERVAL", ret.Interval),
		MaxVersions:   p.positiveInt("TYPOZA_RETENTION_VERSIONS", ret.MaxVersions),
		VersionMaxAge: p.days("TYPOZA_RETENTION_VERSION_DAYS", ret.VersionMaxAge),
		TrashTTL:      p.days("TYPOZA_RETENTION_TRASH_DAYS", ret.TrashTTL),
		ChunkGrace:    p.duration("TYPOZA_RETENTION_CHUNK_GRACE", ret.ChunkGrace),
	}

	if len(p.errs) > 0 {
		return Config{}, fmt.Errorf("配置错误: %w", errors.Join(p.errs...))
	}
	return cfg, nil
}

// DefaultKeyID 由公钥指纹派生 kid:同一私钥的多个实例得到相同 kid,无需额外配置。
func DefaultKeyID(priv ed25519.PrivateKey) string {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// LogValue 只输出非敏感字段;数据库连接串可能含口令,也不输出。
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.Listen),
		slog.String("metricsListen", c.MetricsListen),
		slog.String("blobDriver", c.Blob.Driver),
		slog.String("s3Endpoint", c.Blob.S3Endpoint),
		slog.String("s3Bucket", c.Blob.S3Bucket),
		slog.String("fsDir", c.Blob.FSDir),
		slog.String("jwtKeyId", c.JWTKeyID),
		slog.Bool("registrationOpen", c.RegistrationOpen),
		slog.Int64("quotaBytes", c.QuotaBytes),
		slog.Int("trustedProxies", len(c.TrustedProxies)),
		slog.String("logLevel", c.LogLevel.String()),
		slog.Bool("tracing", c.TracingEnabled),
	)
}

// parser 累积所有错误,最后一次性返回。
type parser struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (p *parser) fail(name, format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
}

func (p *parser) str(name, def string) string {
	v, ok := p.lookup(name)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return def
	}
	return v
}

func (p *parser) required(name string) string {
	v := p.str(name, "")
	if v == "" {
		p.fail(name, "必填,未设置")
	}
	return v
}

func (p *parser) registration(name string) bool {
	switch v := p.str(name, "open"); v {
	case "open":
		return true
	case "closed":
		return false
	default:
		p.fail(name, "只能是 open 或 closed,实际为 %q", v)
		return false
	}
}

func (p *parser) positiveInt64(name string, def int64) int64 {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		p.fail(name, "需要正整数,实际为 %q", v)
		return def
	}
	return n
}

func (p *parser) positiveInt(name string, def int) int {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		p.fail(name, "需要正整数,实际为 %q", v)
		return def
	}
	return n
}

func (p *parser) nonNegativeInt(name string, def int) int {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		p.fail(name, "需要非负整数(0 表示不限),实际为 %q", v)
		return def
	}
	return n
}

func (p *parser) days(name string, def time.Duration) time.Duration {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 36500 {
		p.fail(name, "需要 1~36500 的天数,实际为 %q", v)
		return def
	}
	return time.Duration(n) * 24 * time.Hour
}

func (p *parser) duration(name string, def time.Duration) time.Duration {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		p.fail(name, "需要 Go 时长格式(如 1h、30m,0 表示关闭),实际为 %q", v)
		return def
	}
	return d
}

func (p *parser) boolean(name string, def bool) bool {
	v := p.str(name, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.fail(name, "需要 true 或 false,实际为 %q", v)
		return def
	}
	return b
}

func (p *parser) level(name string) slog.Level {
	v := p.str(name, "info")
	var l slog.Level
	if err := l.UnmarshalText([]byte(v)); err != nil {
		p.fail(name, "只能是 debug、info、warn、error,实际为 %q", v)
		return slog.LevelInfo
	}
	return l
}

// prefixes 解析逗号分隔的 CIDR 列表;单个 IP 视为 /32 或 /128。
func (p *parser) prefixes(name string) []netip.Prefix {
	v := p.str(name, "")
	if v == "" {
		return nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				p.fail(name, "无效 CIDR %q", part)
				continue
			}
			out = append(out, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			p.fail(name, "无效 IP %q", part)
			continue
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out
}

// key 解析 base64 编码的 32 字节密钥;兼容标准与 URL 字母表、带或不带填充(openssl rand -base64 32 的输出可直接用)。
// 错误信息不回显密钥内容。
func (p *parser) key(name string) []byte {
	v := p.required(name)
	if v == "" {
		return nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(v)
		if err != nil {
			continue
		}
		if len(b) != keyLen {
			p.fail(name, "解码后应为 %d 字节,实际 %d 字节", keyLen, len(b))
			return nil
		}
		return b
	}
	p.fail(name, "不是有效的 base64")
	return nil
}

func (p *parser) blob() Blob {
	b := Blob{Driver: p.str("TYPOZA_BLOB_DRIVER", BlobDriverFS)}
	switch b.Driver {
	case BlobDriverFS:
		b.FSDir = p.required("TYPOZA_BLOB_FS_DIR")
	case BlobDriverS3:
		b.S3Endpoint = p.required("TYPOZA_S3_ENDPOINT")
		b.S3Bucket = p.required("TYPOZA_S3_BUCKET")
		b.S3AccessKey = p.required("TYPOZA_S3_ACCESS_KEY")
		b.S3SecretKey = p.required("TYPOZA_S3_SECRET_KEY")
		b.S3Region = p.str("TYPOZA_S3_REGION", "")
		b.S3UseTLS = p.boolean("TYPOZA_S3_USE_TLS", true)
		if strings.Contains(b.S3Endpoint, "://") {
			p.fail("TYPOZA_S3_ENDPOINT", "只写 host:port,不带协议;是否 TLS 由 TYPOZA_S3_USE_TLS 决定")
		}
	default:
		p.fail("TYPOZA_BLOB_DRIVER", "只能是 s3 或 fs,实际为 %q", b.Driver)
	}
	return b
}
