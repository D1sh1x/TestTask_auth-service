package models

import (
	"github.com/google/uuid"
)

type User struct {
	ID uuid.UUID `json:"id" db:"id"`
}

func NewUser() *User {
	return &User{
		ID: uuid.New(),
	}
}
