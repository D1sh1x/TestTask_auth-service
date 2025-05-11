package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	TokenHash string    `json:"token_hash" db:"token_hash"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	IP        string    `json:"ip" db:"ip"`
	IssuedAt  time.Time `json:"issued_at" db:"issued_at"`
	Revoked   bool      `json:"revoked" db:"revoked"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
