package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"github.com/Nutan-Kum12/goblog/pkg/email"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/clients"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/models"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/repository"
)

// AuthService provides authentication business logic
type AuthService struct {
	authRepo      repository.AuthRepository
	userClient    *clients.UserServiceClient
	emailService  *email.EmailService
	jwtSecret     string
	otpLength     int
	otpExpiry     time.Duration
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
}

// NewAuthService creates a new auth service
func NewAuthService(authRepo repository.AuthRepository, jwtSecret string) *AuthService {
	return &AuthService{
		authRepo:      authRepo,
		jwtSecret:     jwtSecret,
		otpLength:     6,
		otpExpiry:     15 * time.Minute,
		tokenExpiry:   1 * time.Hour,
		refreshExpiry: 7 * 24 * time.Hour, // 7 days
	}
}

// NewAuthServiceWithClients creates a new auth service with inter-service clients
func NewAuthServiceWithClients(authRepo repository.AuthRepository, jwtSecret string, userClient *clients.UserServiceClient) *AuthService {
	return &AuthService{
		authRepo:      authRepo,
		userClient:    userClient,
		jwtSecret:     jwtSecret,
		otpLength:     6,
		otpExpiry:     15 * time.Minute,
		tokenExpiry:   1 * time.Hour,
		refreshExpiry: 7 * 24 * time.Hour, // 7 days
	}
}

// NewAuthServiceWithEmailAndClients creates a new auth service with email service and inter-service clients
func NewAuthServiceWithEmailAndClients(authRepo repository.AuthRepository, jwtSecret string, emailService *email.EmailService, userClient *clients.UserServiceClient) *AuthService {
	return &AuthService{
		authRepo:      authRepo,
		userClient:    userClient,
		emailService:  emailService,
		jwtSecret:     jwtSecret,
		otpLength:     6,
		otpExpiry:     15 * time.Minute,
		tokenExpiry:   1 * time.Hour,
		refreshExpiry: 7 * 24 * time.Hour, // 7 days
	}
}

// Custom JWT claims
type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// RegisterUser handles user registration
func (s *AuthService) RegisterUser(ctx context.Context, email, password string) (*models.AuthUser, error) {
	// Validate email format
	if !s.isValidEmail(email) {
		return nil, errors.New("invalid email format")
	}

	// Validate password strength
	if err := s.validatePassword(password); err != nil {
		return nil, err
	}

	// Check if user already exists and is active
	existingUser, err := s.authRepo.GetAuthUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil && existingUser.IsActive {
		return nil, errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := s.hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	// Create user with explicit ObjectID generation
	ObjectID := primitive.NewObjectID()
	userID := ObjectID.Hex()

	// Validate that UserID is not empty (safety check)
	if userID == "" {
		return nil, errors.New("failed to generate valid user ID")
	}

	user := &models.AuthUser{
		ID:           ObjectID,
		UserID:       userID, // Set immediately to avoid empty values
		Email:        strings.ToLower(email),
		PasswordHash: hashedPassword,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Additional validation - ensure no empty UserID gets through
	if user.UserID == "" || len(user.UserID) < 24 {
		return nil, fmt.Errorf("invalid user ID generated: %s", user.UserID)
	} // Debug logging for user creation
	log.Printf("🆔 Creating user with ID: %s, UserID: %s, Email: %s", user.ID.Hex(), user.UserID, user.Email)

	if err := s.authRepo.CreateAuthUser(ctx, user); err != nil {
		log.Printf("❌ Failed to create user: %v", err)
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	log.Printf("✅ User created successfully with UserID: %s", user.UserID)
	return user, nil
}

// GenerateOTP creates and stores an OTP for verification
func (s *AuthService) GenerateOTP(ctx context.Context, userID, purpose string) (*models.OTPRecord, error) {
	otp, err := s.generateRandomOTP()
	if err != nil {
		return nil, fmt.Errorf("error generating OTP: %w", err)
	}

	otpRecord := &models.OTPRecord{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		OTP:       otp,
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(s.otpExpiry),
		CreatedAt: time.Now(),
	}

	if err := s.authRepo.CreateOTP(ctx, otpRecord); err != nil {
		return nil, fmt.Errorf("error storing OTP: %w", err)
	}

	return otpRecord, nil
}

// GenerateAndSendOTP creates an OTP and sends it via email
func (s *AuthService) GenerateAndSendOTP(ctx context.Context, userID, purpose, email string) (*models.OTPRecord, error) {
	otpRecord, err := s.GenerateOTP(ctx, userID, purpose)
	if err != nil {
		return nil, err
	}

	// Send OTP via email if email service is available
	if s.emailService != nil {
		if err := s.emailService.SendOTP(email, otpRecord.OTP, purpose); err != nil {
			log.Printf("⚠️ Warning: Failed to send OTP email to %s: %v", email, err)
			// Don't fail the operation if email fails, just log the OTP
			log.Printf("🔐 OTP for user %s: %s (expires in 15 minutes)", email, otpRecord.OTP)
		} else {
			log.Printf("📧 OTP email sent successfully to %s", email)
		}
	} else {
		// Fallback: log OTP to console if no email service
		log.Printf("🔐 OTP for user %s: %s (expires in 15 minutes)", email, otpRecord.OTP)
	}

	return otpRecord, nil
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*models.AuthUser, error) {
	return s.authRepo.GetAuthUserByID(ctx, userID)
}

// VerifyOTP validates the provided OTP
func (s *AuthService) VerifyOTP(ctx context.Context, userID, otpCode string) error {
	log.Printf("🔍 Looking for OTP record: UserID=%s, OTP=%s", userID, otpCode)

	otpRecord, err := s.authRepo.GetOTP(ctx, userID, otpCode)
	if err != nil {
		log.Printf("❌ Error retrieving OTP from database: %v", err)
		return fmt.Errorf("error retrieving OTP: %w", err)
	}

	if otpRecord == nil {
		log.Printf("❌ No OTP record found for UserID=%s, OTP=%s", userID, otpCode)
		return errors.New("invalid OTP")
	}

	log.Printf("✅ Found OTP record: ID=%s, Used=%v, Expires=%v", otpRecord.ID.Hex(), otpRecord.IsUsed, otpRecord.ExpiresAt)

	if otpRecord.IsUsed {
		log.Printf("❌ OTP already used")
		return errors.New("OTP already used")
	}

	if time.Now().After(otpRecord.ExpiresAt) {
		log.Printf("❌ OTP expired at %v, current time %v", otpRecord.ExpiresAt, time.Now())
		return errors.New("OTP expired")
	}

	// Mark OTP as used
	if err := s.authRepo.MarkOTPAsUsed(ctx, otpRecord.ID); err != nil {
		log.Printf("❌ Error marking OTP as used: %v", err)
		return fmt.Errorf("error marking OTP as used: %w", err)
	}

	// Mark user as verified if this is a registration OTP
	if otpRecord.Purpose == "registration" {
		log.Printf("🔐 Marking user %s as verified", userID)
		if err := s.authRepo.MarkUserAsVerified(ctx, userID); err != nil {
			log.Printf("❌ Error marking user as verified: %v", err)
			return fmt.Errorf("error marking user as verified: %w", err)
		}

		// Notify user service about verification (inter-service communication)
		if err := s.NotifyUserServiceOnVerification(ctx, userID); err != nil {
			// Log error but don't fail the verification process
			log.Printf("⚠️ Warning: Failed to notify user service about verification: %v", err)
		}
	}

	log.Printf("✅ OTP verification completed successfully for user %s", userID)
	return nil
}

// GenerateTokensForUser generates access and refresh tokens for a verified user
func (s *AuthService) GenerateTokensForUser(ctx context.Context, userID string) (string, string, error) {
	log.Printf("🔑 Generating tokens for user %s", userID)

	// Get user details
	user, err := s.authRepo.GetAuthUserByID(ctx, userID)
	if err != nil {
		log.Printf("❌ Error getting user for token generation: %v", err)
		return "", "", fmt.Errorf("error getting user: %w", err)
	}

	// Generate access token
	accessToken, err := s.generateAccessToken(user.ID.Hex(), user.Email)
	if err != nil {
		log.Printf("❌ Error generating access token: %v", err)
		return "", "", fmt.Errorf("error generating access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(ctx, user.ID.Hex())
	if err != nil {
		log.Printf("❌ Error generating refresh token: %v", err)
		return "", "", fmt.Errorf("error generating refresh token: %w", err)
	}

	log.Printf("✅ Tokens generated successfully for user %s", userID)
	return accessToken, refreshToken, nil
}

// LoginUser authenticates a user and returns tokens
func (s *AuthService) LoginUser(ctx context.Context, email, password string) (*models.AuthUser, string, string, error) {
	user, err := s.authRepo.GetAuthUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		return nil, "", "", fmt.Errorf("error retrieving user: %w", err)
	}

	if user == nil || !s.checkPassword(password, user.PasswordHash) {
		return nil, "", "", errors.New("invalid credentials")
	}

	if !user.IsVerified {
		return nil, "", "", errors.New("user not verified")
	}

	if !user.IsActive {
		return nil, "", "", errors.New("user account is inactive")
	}

	// Optional: Validate that user profile exists in user service
	if s.userClient != nil {
		userProfile, err := s.userClient.GetUserById(ctx, user.UserID)
		if err != nil || userProfile == nil || !userProfile.Success {
			log.Printf("⚠️ Warning: User profile not found in user service for UserID: %s", user.UserID)
			// Don't fail login, but log the issue
		}
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user.ID.Hex(), user.Email)
	if err != nil {
		return nil, "", "", fmt.Errorf("error generating access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(ctx, user.ID.Hex())
	if err != nil {
		return nil, "", "", fmt.Errorf("error generating refresh token: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

// ValidateAccessToken validates and parses access token
func (s *AuthService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// RefreshAccessToken generates new access token using refresh token
func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshTokenString string) (string, string, error) {
	refreshToken, err := s.authRepo.GetRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return "", "", fmt.Errorf("error retrieving refresh token: %w", err)
	}

	if refreshToken == nil || refreshToken.IsRevoked {
		return "", "", errors.New("invalid refresh token")
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return "", "", errors.New("refresh token expired")
	}

	// Get user
	user, err := s.authRepo.GetAuthUserByID(ctx, refreshToken.UserID)
	if err != nil {
		return "", "", fmt.Errorf("error retrieving user: %w", err)
	}

	// Generate new tokens
	accessToken, err := s.generateAccessToken(user.ID.Hex(), user.Email)
	if err != nil {
		return "", "", fmt.Errorf("error generating access token: %w", err)
	}

	newRefreshToken, err := s.generateRefreshToken(ctx, user.ID.Hex())
	if err != nil {
		return "", "", fmt.Errorf("error generating refresh token: %w", err)
	}

	// Revoke old refresh token
	if err := s.authRepo.RevokeRefreshToken(ctx, refreshTokenString); err != nil {
		return "", "", fmt.Errorf("error revoking old refresh token: %w", err)
	}

	return accessToken, newRefreshToken, nil
}

// Helper methods
func (s *AuthService) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (s *AuthService) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *AuthService) checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *AuthService) generateRandomOTP() (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(s.otpLength)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0*d", s.otpLength, n), nil
}

func (s *AuthService) generateAccessToken(userID, email string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "goblog-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *AuthService) generateRefreshToken(ctx context.Context, userID string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	tokenString := hex.EncodeToString(tokenBytes)

	refreshToken := &models.RefreshToken{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
		CreatedAt: time.Now(),
	}

	if err := s.authRepo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return "", err
	}

	return tokenString, nil
}

// ForgotPassword generates a password reset token and sends it via email
func (s *AuthService) ForgotPassword(ctx context.Context, email string) (string, error) {
	// Validate email format
	if !s.isValidEmail(email) {
		return "", errors.New("invalid email format")
	}

	// Check if user exists
	user, err := s.authRepo.GetAuthUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		return "", fmt.Errorf("failed to check user: %v", err)
	}
	if user == nil {
		// Don't reveal if email exists or not for security
		return "", nil
	}

	// Generate secure reset token
	resetToken, err := s.generateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate reset token: %v", err)
	}

	// Create password reset record
	passwordReset := &models.PasswordReset{
		ID:        primitive.NewObjectID(),
		Email:     strings.ToLower(email),
		Token:     resetToken,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		IsUsed:    false,
		CreatedAt: time.Now(),
	}

	// Save reset token to database
	err = s.authRepo.CreatePasswordReset(ctx, passwordReset)
	if err != nil {
		return "", fmt.Errorf("failed to save reset token: %v", err)
	}

	// Send password reset email
	if s.emailService != nil {
		err = s.emailService.SendPasswordReset(email, resetToken)
		if err != nil {
			log.Printf("❌ Failed to send password reset email to %s: %v", email, err)
			// Don't return error to avoid revealing email existence
		} else {
			log.Printf("📧 Password reset email sent successfully to %s", email)
		}
	} else {
		// Fallback: log reset token to console if no email service
		log.Printf("🔐 [DEV MODE] Password Reset Token for %s: %s (expires in 1 hour)", email, resetToken)
	}

	return resetToken, nil
}

// ResetPassword resets user password using reset token
func (s *AuthService) ResetPassword(ctx context.Context, email, resetToken, newPassword string) error {
	// Validate inputs
	if !s.isValidEmail(email) {
		return errors.New("invalid email format")
	}
	if resetToken == "" {
		return errors.New("reset token is required")
	}
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	// Get and validate reset token
	passwordReset, err := s.authRepo.GetPasswordReset(ctx, strings.ToLower(email), resetToken)
	if err != nil {
		return fmt.Errorf("failed to get reset token: %v", err)
	}
	if passwordReset == nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token is already used
	if passwordReset.IsUsed {
		return errors.New("reset token has already been used")
	}

	// Check if token is expired
	if time.Now().After(passwordReset.ExpiresAt) {
		return errors.New("reset token has expired")
	}

	// Get user
	user, err := s.authRepo.GetAuthUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		return fmt.Errorf("failed to get user: %v", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()

	err = s.authRepo.UpdateAuthUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user password: %v", err)
	}

	// Mark reset token as used
	err = s.authRepo.MarkPasswordResetAsUsed(ctx, passwordReset.ID)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to mark reset token as used: %v", err)
		// Don't return error as password is already updated
	}

	// Revoke all existing refresh tokens for security
	err = s.authRepo.RevokeAllUserTokens(ctx, user.UserID)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to revoke user tokens: %v", err)
		// Don't return error as password is already updated
	}

	log.Printf("✅ Password successfully reset for user: %s", email)
	return nil
}

// generateSecureToken generates a cryptographically secure random token
func (s *AuthService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Inter-service communication methods

// NotifyUserServiceOnVerification notifies user service when user is verified
func (s *AuthService) NotifyUserServiceOnVerification(ctx context.Context, userID string) error {
	if s.userClient == nil {
		return nil // Skip if user service is not available
	}

	_, err := s.userClient.UpdateVerificationStatus(ctx, userID, true)

	if err != nil {
		return fmt.Errorf("failed to notify user service about verification: %w", err)
	}

	return nil
}

// GetUserProfileFromUserService gets user profile from user service
func (s *AuthService) GetUserProfileFromUserService(ctx context.Context, userID string) (interface{}, error) {
	if s.userClient == nil {
		return nil, errors.New("user service client not available")
	}

	resp, err := s.userClient.GetUserProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	return resp, nil
}

// DeleteUserFromUserService deletes user from user service
func (s *AuthService) DeleteUserFromUserService(ctx context.Context, userID string) error {
	if s.userClient == nil {
		return nil // Skip if user service is not available
	}

	_, err := s.userClient.DeleteUserAccount(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user from user service: %w", err)
	}

	return nil
}

// DeleteUserCompletely deletes user from both auth and user services
func (s *AuthService) DeleteUserCompletely(ctx context.Context, email string) error {
	log.Printf("🗑️ Starting complete user deletion for email: %s", email)

	// Get user info before deletion
	user, err := s.authRepo.GetAuthUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		return fmt.Errorf("failed to get user info: %v", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	// 1. Delete from user service first (profile data)
	if s.userClient != nil {
		if err := s.DeleteUserFromUserService(ctx, user.UserID); err != nil {
			log.Printf("⚠️ Warning: Failed to delete user profile: %v", err)
			// Continue with auth deletion even if profile deletion fails
		} else {
			log.Printf("✅ User profile deleted for UserID: %s", user.UserID)
		}
	}

	// 2. Clean up auth-related data (revoke tokens)
	if err := s.authRepo.RevokeAllUserTokens(ctx, user.UserID); err != nil {
		log.Printf("⚠️ Warning: Failed to revoke refresh tokens: %v", err)
	}

	// 3. Mark auth user as inactive instead of hard delete (safer approach)
	user.IsActive = false
	user.UpdatedAt = time.Now()
	if err := s.authRepo.UpdateAuthUser(ctx, user); err != nil {
		return fmt.Errorf("failed to deactivate auth user: %v", err)
	}

	log.Printf("✅ User completely deleted/deactivated: %s (UserID: %s)", email, user.UserID)
	return nil
}
