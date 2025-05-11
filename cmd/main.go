package main

import (
	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/service"
	"auth-service/internal/storage"
	"database/sql"
	"fmt"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
)

func main() {

	cfg := config.NewConfig()

	connStr := cfg.ConnectionString

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	refreshStore := storage.NewRefreshTokenStore(db)
	tokenService := service.NewTokenService(cfg.JWT.SecretKey, cfg.WebHook.Url, refreshStore)
	authHandler := handler.NewAuthHandler(tokenService)

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.POST("/auth/token", authHandler.GetTokens)
	e.POST("/auth/token/refresh", authHandler.RefreshTokens)
	e.GET("/auth/me", authHandler.GetCurrentUser)
	e.POST("/auth/logout", authHandler.Logout)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%s", cfg.HTTPServer.Port)))
}
