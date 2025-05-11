package service

import (
	"auth-service/internal/models"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenService struct {
	secretKey    []byte
	webhookURL   string
	refreshStore RefreshTokenStore
}

type RefreshTokenStore interface {
	Store(token *models.RefreshToken) error
	GetByHash(hash string) (*models.RefreshToken, error)
	Revoke(userID uuid.UUID) error
}

type IPChangeNotification struct {
	UserID    uuid.UUID `json:"user_id"`
	OldIP     string    `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	Timestamp time.Time `json:"timestamp"`
}

func NewTokenService(secretKey string, webhookURL string, store RefreshTokenStore) *TokenService {
	return &TokenService{
		secretKey:    []byte(secretKey),
		webhookURL:   webhookURL,
		refreshStore: store,
	}
}

func (s *TokenService) GenerateTokenPair(userID uuid.UUID, userAgent string, ip string) (*models.TokenPair, error) {
	accessToken, err := s.generateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.New().String()
	refreshTokenHash := s.hashRefreshToken(refreshToken)

	err = s.refreshStore.Store(&models.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: refreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		IssuedAt:  time.Now(),
		Revoked:   false,
	})
	if err != nil {
		return nil, err
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(refreshToken)),
	}, nil
}

func (s *TokenService) notifyIPChange(userID uuid.UUID, oldIP, newIP string) error {
	notification := IPChangeNotification{
		UserID:    userID,
		OldIP:     oldIP,
		NewIP:     newIP,
		Timestamp: time.Now(),
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("webhook notification failed")
	}

	return nil
}

func (s *TokenService) RefreshTokens(refreshTokenBase64 string, userAgent string, ip string) (*models.TokenPair, error) {
	refreshTokenBytes, err := base64.StdEncoding.DecodeString(refreshTokenBase64)
	if err != nil {
		return nil, errors.New("invalid refresh token format")
	}
	refreshToken := string(refreshTokenBytes)

	storedToken, err := s.refreshStore.GetByHash(s.hashRefreshToken(refreshToken))
	if err != nil {
		return nil, err
	}

	if storedToken.UserAgent != userAgent {
		err = s.refreshStore.Revoke(storedToken.UserID)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("user agent mismatch")
	}

	if storedToken.IP != ip {
		go func() {
			if err := s.notifyIPChange(storedToken.UserID, storedToken.IP, ip); err != nil {
				println("Failed to send webhook notification:", err.Error())
			}
		}()
	}

	return s.GenerateTokenPair(storedToken.UserID, userAgent, ip)
}

func (s *TokenService) ValidateAccessToken(tokenString string) (*uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			return nil, err
		}
		return &userID, nil
	}

	return nil, errors.New("invalid token")
}

func (s *TokenService) generateAccessToken(userID uuid.UUID) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID.String()
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *TokenService) hashRefreshToken(token string) string {
	hash := sha512.New()
	hash.Write([]byte(token))
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *TokenService) RevokeTokens(userID uuid.UUID) error {
	return s.refreshStore.Revoke(userID)
}
