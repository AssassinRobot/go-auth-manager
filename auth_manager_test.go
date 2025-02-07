package auth_manager_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	auth_manager "github.com/tahadostifam/go-auth-manager"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func getRedisTestInstance(callback func(_redisClient *redis.Client)) {
	dockerContainerEnvVariables := []string{}

	err := os.Setenv("ENV", "test")
	if err != nil {
		log.Fatalf("Could not set the environment variable to test: %s", err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not construct pool: %s", err)
	}

	var client *redis.Client

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "latest",
		Env:        dockerContainerEnvVariables,
	})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	// Kill the container
	// defer func() {
	// 	if err = pool.Purge(resource); err != nil {
	// 		log.Fatalf("Could not purge resource: %s", err)
	// 	}
	// }()

	err = pool.Retry(func() error {
		ipAddr := resource.Container.NetworkSettings.IPAddress + ":6379"

		fmt.Printf("Docker redis container network ip address: %s\n", ipAddr)

		client = redis.NewClient(&redis.Options{
			Addr: ipAddr,
			DB:   0,
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		log.Fatalf("Could not connect to Redis: %s", err)
	}

	callback(client)
}

var redisClient *redis.Client

type AuthManagerTestSuite struct {
	suite.Suite

	authManager auth_manager.AuthManager
}

func TestMain(m *testing.M) {
	getRedisTestInstance(func(_redisClient *redis.Client) {
		redisClient = _redisClient
		m.Run()
	})
}
func (s *AuthManagerTestSuite) SetupSuite() {
	s.authManager = auth_manager.NewAuthManager(redisClient, auth_manager.AuthManagerOpts{
		PrivateKey: "private-key",
	})
}

func (s *AuthManagerTestSuite) Test_GenerateAndDecodeToken() {
	// Generate
	ctx := context.TODO()
	tokenType := auth_manager.VerifyEmail
	expiration := time.Minute * 2
	payload := &auth_manager.TokenPayload{
		UUID:      uuid.NewString(),
		TokenType: tokenType,
		CreatedAt: time.Now(),
	}

	token, err := s.authManager.GeneratePlainToken(ctx, tokenType, payload, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodePlainToken(ctx, token, tokenType)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.UUID, payload.UUID)
	require.Equal(s.T(), decoded.TokenType, payload.TokenType)
	require.NotEmpty(s.T(), decoded.CreatedAt)
}

func (s *AuthManagerTestSuite) Test_GenerateAndDecodeAccessTokenAndCompare() {
	// Generate
	ctx := context.TODO()
	uuid := uuid.NewString()
	expiration := time.Minute * 10
	role := "admin"

	token, err := s.authManager.GenerateAccessToken(ctx, uuid, role, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodeAccessToken(ctx, token)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.Payload.UUID, uuid)
	require.Equal(s.T(), decoded.Payload.Role, role)
	require.Equal(s.T(), decoded.Payload.TokenType, auth_manager.AccessToken)
	require.NotEmpty(s.T(), decoded.Payload.CreatedAt)

	token1, err := s.authManager.GenerateAccessToken(ctx, uuid, role, expiration)
	require.NoError(s.T(), err)
	require.NotEqual(s.T(), token1, token)

	token2, err := s.authManager.GenerateAccessToken(ctx, "another", role, expiration)
	require.NoError(s.T(), err)
	require.NotEqual(s.T(), token2, token)
	require.NotEqual(s.T(), token2, token1)

}

func (s *AuthManagerTestSuite) Test_SetAndCheckAccessToken() {
	//set
	ctx := context.TODO()
	err := s.authManager.SetAccessTokenInBlackList(ctx, "accessToken", time.Minute*5)
	require.NoError(s.T(), err)

	// check
	isBlacklisted := s.authManager.IsAccessTokenBlacklisted(ctx, "accessToken")
	s.True(isBlacklisted)
}

func (s *AuthManagerTestSuite) Test_RefreshToken() {
	// Generate
	ctx := context.TODO()
	expiration := time.Minute * 2
	payload := &auth_manager.RefreshTokenPayload{
		IPAddress:  "ip-address",
		UserAgent:  "user-agent",
		UserID:     1,
		LoggedInAt: time.Duration(time.Now().UnixMilli()),
	}

	token, err := s.authManager.GenerateRefreshToken(ctx, payload, expiration)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	// Decode
	decoded, err := s.authManager.DecodeRefreshToken(ctx, token)
	require.NoError(s.T(), err)
	require.Equal(s.T(), decoded.IPAddress, payload.IPAddress)
	require.Equal(s.T(), decoded.UserAgent, payload.UserAgent)
	require.NotEmpty(s.T(), decoded.LoggedInAt)
	require.NotEmpty(s.T(), decoded.UserID)

	// Remove
	// err = s.authManager.RemoveRefreshToken(ctx, uuid, token)
	// require.NoError(s.T(), err)

	// Terminates
	err = s.authManager.TerminateRefreshTokens(ctx, token)
	require.NoError(s.T(), err)
}

func (s *AuthManagerTestSuite) Test_GenerateAndCompareVerificationCode() {
	// Generate
	ctx := context.TODO()

	uuid := uuid.NewString()

	storedCode, generateCodeError := s.authManager.GenerateVerificationCode(ctx, uuid, 6, 2*time.Minute)
	require.NoError(s.T(), generateCodeError)

	//Compare

	isValid, compareError := s.authManager.CompareVerificationCode(ctx, uuid, storedCode)
	require.NoError(s.T(), compareError)
	require.True(s.T(), isValid)
}
func TestAuthManagerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerTestSuite))
}
