package storage

import (
	"auth-service/internal/models"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

type RefreshTokenStore struct {
	db *sql.DB
}

func NewRefreshTokenStore(db *sql.DB) *RefreshTokenStore {
	return &RefreshTokenStore{
		db: db,
	}
}

func (s *RefreshTokenStore) Store(token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, user_agent, ip, issued_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.Exec(query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.UserAgent,
		token.IP,
		token.IssuedAt,
		token.Revoked,
	)
	return err
}

func (s *RefreshTokenStore) GetByHash(hash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, user_agent, ip, issued_at, revoked
		FROM refresh_tokens
		WHERE token_hash = $1 AND revoked = false
	`
	token := &models.RefreshToken{}
	err := s.db.QueryRow(query, hash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.UserAgent,
		&token.IP,
		&token.IssuedAt,
		&token.Revoked,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *RefreshTokenStore) Revoke(userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1
	`
	_, err := s.db.Exec(query, userID)
	return err
}
