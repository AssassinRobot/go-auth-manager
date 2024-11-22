package auth_manager

import (
	"context"
	"strconv"
	"time"
)

// The GenerateVerificationCode method stores a verification code with expire time in Redis.
func (t *authManager) GenerateVerificationCode(ctx context.Context, key string, codeLengths int, expiresAt time.Duration) (string, error) {
	code := generateRandomNumber(codeLengths)

	_, err := t.redisClient.Set(ctx, key, code, expiresAt).Result()
	if err != nil {
		return "", err
	}

	return strconv.Itoa(code), nil
}

// The CompareVerificationCode method compare input code with stored code in Redis.
func (t *authManager) CompareVerificationCode(ctx context.Context, key, code string) (bool, error) {
	storedCode, err := t.redisClient.Get(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if storedCode != code {
		return false, ErrCodeIsInValid
	}

	return true, nil
}
