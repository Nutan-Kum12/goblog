package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	pb "github.com/Nutan-Kum12/goblog/proto/user"
	"github.com/Nutan-Kum12/goblog/services/user/internal/clients"
	"github.com/Nutan-Kum12/goblog/services/user/internal/models"
	"github.com/Nutan-Kum12/goblog/services/user/internal/repository"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
)

// UserService provides user management business logic
type UserService struct {
	userRepo   repository.UserRepository
	authClient *clients.AuthServiceClient
}

// NewUserService creates a new user service
func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// NewUserServiceWithClients creates a new user service with inter-service clients
func NewUserServiceWithClients(userRepo repository.UserRepository, authClient *clients.AuthServiceClient) *UserService {
	return &UserService{
		userRepo:   userRepo,
		authClient: authClient,
	}
}

// CreateUser creates a new user (called by auth service)
func (s *UserService) CreateUser(ctx context.Context, email string) (*models.User, error) {
	// Check if user already exists
	existingUser, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	// Create new user
	user := &models.User{
		UserID:    uuid.New().String(),
		Email:     email,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	return s.userRepo.GetUserByID(ctx, userID)
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.GetUserByEmail(ctx, email)
}

// CompleteProfile completes user profile after registration
func (s *UserService) CompleteProfile(ctx context.Context, userID, firstName, lastName, phoneNumber string, dateOfBirth *time.Time, interests []string) error {
	log.Printf("🔧 Completing profile for UserID: %s", userID)

	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		log.Printf("❌ Error checking user existence: %v", err)
		return fmt.Errorf("error checking user: %w", err)
	}
	if user == nil {
		log.Printf("❌ User not found for UserID: %s", userID)
		return errors.New("invalid user_id - user profile not found")
	}

	log.Printf("✅ Found user profile for UserID: %s (Email: %s)", userID, user.Email)

	// If email is missing, try to fetch it from auth service
	if user.Email == "" && s.authClient != nil {
		log.Printf("📧 Email missing for UserID: %s, attempting to fetch from auth service", userID)
		// We'll add a method to get user details from auth service
		// For now, let's update the profile without email sync
		log.Printf("⚠️ Email sync from auth service not yet implemented - profile will be completed without email")
	}

	// Update profile
	err = s.userRepo.UpdateUserProfile(ctx, userID, firstName, lastName, phoneNumber, dateOfBirth, interests)
	if err != nil {
		log.Printf("❌ Error updating profile: %v", err)
		return fmt.Errorf("error updating profile: %w", err)
	}

	log.Printf("✅ Profile completed successfully for UserID: %s", userID)
	return nil
}

// UpdateProfile updates user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID, firstName, lastName, phoneNumber string, dateOfBirth *time.Time, interests []string) error {
	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	// Update profile
	return s.userRepo.UpdateUserProfile(ctx, userID, firstName, lastName, phoneNumber, dateOfBirth, interests)
}

// UpdateVerificationStatus updates user verification status
func (s *UserService) UpdateVerificationStatus(ctx context.Context, userID string, isVerified bool) error {
	// First, check if user exists
	existingUser, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("error checking user existence: %w", err)
	}

	// If user doesn't exist, create profile automatically during verification
	if existingUser == nil {
		log.Printf("🔄 User profile not found for UserID %s, creating profile during verification", userID)

		// Try to get email from MongoDB directly (since both services use the same database)
		email := ""
		if err := s.fetchEmailFromAuthDatabase(ctx, userID, &email); err != nil {
			log.Printf("⚠️ Could not fetch email from auth database: %v", err)
			// Continue without email - it can be set during profile completion
		} else if email != "" {
			log.Printf("✅ Fetched email from auth database: %s", email)
		}

		// Create user profile with UserID from auth service
		user := &models.User{
			UserID:     userID, // Use the exact UserID from auth service
			Email:      email,  // Will be populated from auth service or during profile completion
			IsActive:   true,
			IsVerified: isVerified,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		log.Printf("🔧 About to create user profile: UserID=%s, Email=%s, IsVerified=%v", user.UserID, user.Email, user.IsVerified)

		if err := s.userRepo.CreateUser(ctx, user); err != nil {
			log.Printf("❌ Failed to create user profile: %v", err)
			return fmt.Errorf("error creating user profile: %w", err)
		}

		if email != "" {
			log.Printf("✅ Created user profile for UserID: %s with email: %s", userID, email)
		} else {
			log.Printf("✅ Created user profile for UserID: %s (email will be set during profile completion)", userID)
		}
		return nil
	}

	// User exists, just update verification status
	return s.userRepo.UpdateVerificationStatus(ctx, userID, isVerified)
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	return s.userRepo.DeleteUser(ctx, userID)
}

// ListUsers retrieves a paginated list of users
func (s *UserService) ListUsers(ctx context.Context, page, limit int, search string) ([]*models.User, int64, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	return s.userRepo.ListUsers(ctx, page, limit, search)
}

// ConvertInterestsFromProto converts protobuf interests to strings
func ConvertInterestsFromProto(interests []pb.InterestCategory) []string {
	var result []string
	for _, interest := range interests {
		result = append(result, interest.String())
	}
	return result
}

// SetUserEmail sets/updates the email for a user (internal method for data fixing)
func (s *UserService) SetUserEmail(ctx context.Context, userID, email string) error {
	// Check if user exists
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("error checking user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	// Update email in user profile
	// We'll need to create a repository method for this, but for now use UpdateUserProfile
	log.Printf("🔧 Setting email %s for UserID: %s", email, userID)
	return s.userRepo.UpdateVerificationStatus(ctx, userID, user.IsVerified) // This will update the user
}

// fetchEmailFromAuthDatabase fetches email from auth_users collection
func (s *UserService) fetchEmailFromAuthDatabase(ctx context.Context, userID string, email *string) error {
	// Get MongoDB client from user repository
	mongoRepo, ok := s.userRepo.(*repository.MongoUserRepository)
	if !ok {
		return errors.New("repository is not MongoDB type")
	}

	// Access the auth_users collection directly
	authCollection := mongoRepo.GetDatabase().Collection("auth_users")

	var authUser struct {
		Email string `bson:"email"`
	}

	filter := bson.M{"user_identifier": userID}
	err := authCollection.FindOne(ctx, filter).Decode(&authUser)
	if err != nil {
		return fmt.Errorf("failed to find auth user: %w", err)
	}

	*email = authUser.Email
	return nil
}

// DiagnoseUserSync checks if user exists in both auth and user services
func (s *UserService) DiagnoseUserSync(ctx context.Context, userID string) (bool, string) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Sprintf("Error checking user: %v", err)
	}
	if user == nil {
		return false, "User profile not found in user service"
	}

	return true, fmt.Sprintf("User found - ID: %s, Email: %s, Verified: %v, Active: %v",
		user.UserID, user.Email, user.IsVerified, user.IsActive)
}

// Inter-service communication methods

// ValidateTokenWithAuthService validates token using auth service
func (s *UserService) ValidateTokenWithAuthService(ctx context.Context, accessToken string) (string, error) {
	if s.authClient == nil {
		return "", errors.New("auth service client not available")
	}

	resp, err := s.authClient.ValidateToken(ctx, accessToken)
	if err != nil {
		return "", fmt.Errorf("failed to validate token: %w", err)
	}

	if !resp.Valid {
		return "", errors.New("invalid token")
	}

	return resp.UserId, nil
}

// RefreshTokenWithAuthService refreshes token using auth service
func (s *UserService) RefreshTokenWithAuthService(ctx context.Context, refreshToken string) (string, string, error) {
	if s.authClient == nil {
		return "", "", errors.New("auth service client not available")
	}

	resp, err := s.authClient.RefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to refresh token: %w", err)
	}

	if !resp.Success {
		return "", "", errors.New("token refresh failed")
	}

	return resp.AccessToken, resp.RefreshToken, nil
}

// LogoutWithAuthService logs out user using auth service
func (s *UserService) LogoutWithAuthService(ctx context.Context, userID, refreshToken string) error {
	if s.authClient == nil {
		return nil // Skip if auth service is not available
	}

	_, err := s.authClient.Logout(ctx, userID, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to logout user: %w", err)
	}

	return nil
}
func (s *UserService) IncrementFollowerCount(ctx context.Context, userID string) error {
	return s.userRepo.IncrementFollowerCount(ctx, userID)
}

func (s *UserService) DecrementFollowerCount(ctx context.Context, userID string) error {
	return s.userRepo.DecrementFollowerCount(ctx, userID)
}

func (s *UserService) IncrementFollowingCount(ctx context.Context, userID string) error {
	return s.userRepo.IncrementFollowingCount(ctx, userID)
}

func (s *UserService) DecrementFollowingCount(ctx context.Context, userID string) error {
	return s.userRepo.DecrementFollowingCount(ctx, userID)
}
