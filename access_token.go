package auth_manager

import (
	"context"
	"strings"
	"time"

	uid "github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
)

var TokenEncodingAlgorithm = jwt.SigningMethodHS512

type AccessTokenClaims struct {
	Payload TokenPayload
	jwt.RegisteredClaims
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) GenerateAccessToken(ctx context.Context, uuid, role string, expiresAt time.Duration) (string, error) {
	now := time.Now()

	claims := AccessTokenClaims{
		Payload: TokenPayload{
			UUID:      uuid,
			Role:      role,
			TokenType: AccessToken,
			CreatedAt: time.Now(),
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresAt)),
			Issuer:    "go-auth-manager",
			ID:uid.NewString(),
		},
	}
	
	jwtToken, err := jwt.NewWithClaims(TokenEncodingAlgorithm, claims).SignedString([]byte(t.opts.PrivateKey))
	if err != nil {
		return "", nil
	}

	return jwtToken, nil
}

// The GenerateAccessToken method is used to generate Stateless JWT Token.
// Notice that access tokens are not store at Redis Store and they are stateless!
func (t *authManager) DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			return []byte(t.opts.PrivateKey), nil
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, ErrTokenExpired
		}

		return nil, ErrInvalidToken
	}

	expr, err := jwtToken.Claims.GetExpirationTime()
	if err != nil || expr == nil {
		return nil, ErrNoExpiration
	}

	now := time.Now()

	if expr.Time.Before(now) {
		return nil, ErrTokenExpired
	}

	if jwtToken.Valid {
		if claims.Payload.TokenType != AccessToken {
			return nil, ErrInvalidTokenType
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}

func (t *authManager) SetAccessTokenInBlackList(ctx context.Context, accessToken string, expiresAt time.Duration) error {
	err := t.redisClient.Set(ctx, accessToken, "blackList", expiresAt).Err()
	return err
}

func (t *authManager) IsAccessTokenBlacklisted(ctx context.Context, accessToken string) bool {
	result := t.redisClient.Exists(ctx, accessToken)
	return result.Val() == 1
}
