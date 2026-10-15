package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ComeHereToSee/typoza-backend/internal/ids"
)

// 访问令牌参数(同步协议 §3.1)。
const (
	TokenIssuer   = "typoza"
	TokenAudience = "typoza-api"
	AccessTTL     = 15 * time.Minute

	// 多实例之间时钟可能有几秒偏差,iat/exp 校验留 30 秒余量。
	clockLeeway = 30 * time.Second
)

// 访问令牌校验失败的两类结果:过期(客户端应刷新)与其它无效(客户端应重新登录)。
var (
	ErrAccessExpired = errors.New("访问令牌已过期")
	ErrAccessInvalid = errors.New("访问令牌无效")
)

// accessClaims 是访问令牌载荷。aud 按协议写成单个字符串而不是数组,
// 所以不用 jwt.RegisteredClaims(它的 Audience 默认序列化为数组)。
type accessClaims struct {
	Issuer    string           `json:"iss"`
	Audience  string           `json:"aud"`
	Subject   string           `json:"sub"`
	DeviceID  string           `json:"did"`
	IssuedAt  *jwt.NumericDate `json:"iat"`
	ExpiresAt *jwt.NumericDate `json:"exp"`
}

func (c *accessClaims) GetExpirationTime() (*jwt.NumericDate, error) { return c.ExpiresAt, nil }
func (c *accessClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return c.IssuedAt, nil }
func (c *accessClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (c *accessClaims) GetIssuer() (string, error)                   { return c.Issuer, nil }
func (c *accessClaims) GetSubject() (string, error)                  { return c.Subject, nil }
func (c *accessClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}

// Signer 签发与校验访问令牌。只认 EdDSA,防止算法混淆攻击(例如把公钥当 HMAC 密钥伪造 HS256 令牌)。
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// NewSigner 用 Ed25519 私钥与密钥 ID 创建签发器。
func NewSigner(priv ed25519.PrivateKey, kid string) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Ed25519 私钥长度应为 %d,实际 %d", ed25519.PrivateKeySize, len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("无法从私钥导出 Ed25519 公钥")
	}
	if kid == "" {
		return nil, errors.New("JWT 密钥 ID 不能为空")
	}
	return &Signer{priv: priv, pub: pub, kid: kid}, nil
}

// Issue 签发访问令牌,有效期 AccessTTL。
func (s *Signer) Issue(userID, deviceID string, now time.Time) (string, error) {
	claims := &accessClaims{
		Issuer:    TokenIssuer,
		Audience:  TokenAudience,
		Subject:   userID,
		DeviceID:  deviceID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(AccessTTL)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.priv)
	if err != nil {
		return "", fmt.Errorf("签发访问令牌: %w", err)
	}
	return signed, nil
}

// Verify 校验访问令牌,返回 userID 与 deviceID。
// 签名先于有效期校验:篡改过的过期令牌返回 ErrAccessInvalid,而不是 ErrAccessExpired。
func (s *Signer) Verify(token string, now time.Time) (userID, deviceID string, err error) {
	claims := &accessClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithAudience(TokenAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	_, err = parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if kid, _ := t.Header["kid"].(string); kid != s.kid {
			return nil, fmt.Errorf("未知的 kid %q", kid)
		}
		return s.pub, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", "", ErrAccessExpired
		}
		return "", "", fmt.Errorf("%w: %w", ErrAccessInvalid, err)
	}
	if !ids.Valid(claims.Subject) || !ids.Valid(claims.DeviceID) {
		return "", "", fmt.Errorf("%w: sub 或 did 不是规范 UUID", ErrAccessInvalid)
	}
	return claims.Subject, claims.DeviceID, nil
}
