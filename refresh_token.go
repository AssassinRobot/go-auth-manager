package auth_manager

import (
	"context"
	"encoding/json"
	"time"
)

const refreshTokenByteLength = 32

// func generateHashKey(uuid string) string {
// 	return fmt.Sprintf("refresh_token:%s", uuid)
// }

type RefreshTokenPayload struct {
	IPAddress  string        `json:"ipAddress"`
	UserAgent  string        `json:"userAgent"`
	UserID     uint          `json:"userID"`
	LoggedInAt time.Duration `json:"loggedInAt"`
}

// The GenerateToken method generates a random string with base64 with a static byte length
// and stores it in the Redis store with provided expiration duration.
func (t *authManager) GenerateRefreshToken(ctx context.Context, payload *RefreshTokenPayload, expiresAt time.Duration) (string, error) {
	// Generate random string
	refreshToken, err := generateRandomString(refreshTokenByteLength)
	if err != nil {
		return "", err
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", ErrEncodingPayload
	}

	err = t.redisClient.Set(ctx, refreshToken, payloadJson, expiresAt).Err()
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (t *authManager) DecodeRefreshToken(ctx context.Context, token string) (*RefreshTokenPayload, error) {
	payloadStr, err := t.redisClient.Get(ctx, token).Result()
	if err != nil {
		return nil, ErrInvalidToken
	}

	var payload *RefreshTokenPayload

	err = json.Unmarshal([]byte(payloadStr), &payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return payload, nil
}

func (t *authManager) TerminateRefreshTokens(ctx context.Context, token string) error {
	return t.redisClient.Del(ctx, token).Err()
}
