package handler

import (
	"auth-service/internal/service"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	tokenService *service.TokenService
}

func NewAuthHandler(tokenService *service.TokenService) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
	}
}

func (h *AuthHandler) GetTokens(c echo.Context) error {
	userIDStr := c.QueryParam("user_id")
	if userIDStr == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "user_id is required"})
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user_id format"})
	}

	userAgent := c.Request().UserAgent()
	ip := c.RealIP()

	tokens, err := h.tokenService.GenerateTokenPair(userID, userAgent, ip)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) RefreshTokens(c echo.Context) error {
	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
	}

	userAgent := c.Request().UserAgent()
	ip := c.RealIP()

	tokens, err := h.tokenService.RefreshTokens(refreshToken, userAgent, ip)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) GetCurrentUser(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid authorization header"})
	}

	userID, err := h.tokenService.ValidateAccessToken(tokenParts[1])
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"user_id": userID.String()})
}

func (h *AuthHandler) Logout(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid authorization header"})
	}

	userID, err := h.tokenService.ValidateAccessToken(tokenParts[1])
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	err = h.tokenService.RevokeTokens(*userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "logged out successfully"})
}
