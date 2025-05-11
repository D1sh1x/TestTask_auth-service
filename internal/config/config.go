package config

import (
	"fmt"
	"log"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env        string `yaml:"env"`
	Storage    `yaml:"storage"`
	HTTPServer `yaml:"http_server"`
	JWT        `yaml:"jwt"`
	WebHook    `yaml:"webhook"`
}

type Storage struct {
	Host             string `yaml:"host"`
	Port             string `yaml:"port"`
	Database         string `yaml:"database"`
	Username         string `yaml:"username"`
	Password         string `yaml:"password"`
	SSL              string `yaml:"ssl"`
	ConnectionString string
}

type HTTPServer struct {
	Port string `yaml:"port"`
}

type JWT struct {
	SecretKey         string
	Access_token_ttl  string `yaml:"access_token_ttl"`
	Refresh_token_ttl string `yaml:"refresh_token_ttl"`
}

type WebHook struct {
	Url string `yaml:"url"`
}

func NewConfig() *Config {
	cfg := Config{}
	err := godotenv.Load("local.env")
	if err != nil {
		log.Fatalf("Error load config: %s", err)
	}
	configPath := os.Getenv("CONFIG_PATH")
	db_login := os.Getenv("DB_LOGIN")
	db_password := os.Getenv("DB_PASSWORD")
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if configPath == "" {
		log.Fatal("Config path is not set")
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("config file %s does not exists", err)
	}
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("cannot read config: %s", err)
	}
	cfg.Storage.Username = db_login
	cfg.Storage.Password = db_password
	cfg.Storage.ConnectionString = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Storage.Host,
		cfg.Storage.Port,
		cfg.Storage.Username,
		cfg.Storage.Password,
		cfg.Storage.Database,
		cfg.Storage.SSL)
	cfg.JWT.SecretKey = jwtSecret
	return &cfg
}
