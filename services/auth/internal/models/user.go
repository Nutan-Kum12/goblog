package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthUser represents authentication data in MongoDB
type AuthUser struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       string             `bson:"user_identifier" json:"user_id"` // Completely new field name
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"password_hash" json:"-"` // Never return password in JSON
	IsVerified   bool               `bson:"is_verified" json:"is_verified"`
	IsActive     bool               `bson:"is_active" json:"is_active"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
}

// OTPRecord represents OTP verification data
type OTPRecord struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    string             `bson:"user_identifier" json:"user_id"` // Updated field name
	OTP       string             `bson:"otp" json:"-"`                   // Never return OTP in JSON
	Purpose   string             `bson:"purpose" json:"purpose"`         // "registration", "password_reset"
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	IsUsed    bool               `bson:"is_used" json:"is_used"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    string             `bson:"user_identifier" json:"user_id"` // Updated field name
	Token     string             `bson:"token" json:"token"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	IsRevoked bool               `bson:"is_revoked" json:"is_revoked"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// PasswordReset represents a password reset token
type PasswordReset struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email     string             `bson:"email" json:"email"`
	Token     string             `bson:"token" json:"token"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	IsUsed    bool               `bson:"is_used" json:"is_used"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// TokenBlacklist represents blacklisted tokens
type TokenBlacklist struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Token     string             `bson:"token" json:"token"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}
