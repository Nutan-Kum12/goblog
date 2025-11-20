package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/Nutan-Kum12/goblog/services/auth/internal/models"
)

// AuthRepository defines the interface for auth database operations
type AuthRepository interface {
	// Auth user operations
	CreateAuthUser(ctx context.Context, user *models.AuthUser) error
	GetAuthUserByID(ctx context.Context, userID string) (*models.AuthUser, error)
	GetAuthUserByEmail(ctx context.Context, email string) (*models.AuthUser, error)
	UpdateAuthUser(ctx context.Context, user *models.AuthUser) error
	UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error
	MarkUserAsVerified(ctx context.Context, userID string) error

	// OTP operations
	CreateOTP(ctx context.Context, otp *models.OTPRecord) error
	GetOTP(ctx context.Context, userID, otpCode string) (*models.OTPRecord, error)
	MarkOTPAsUsed(ctx context.Context, id primitive.ObjectID) error
	DeleteExpiredOTPs(ctx context.Context) error

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	DeleteExpiredTokens(ctx context.Context) error

	// Password reset operations
	CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error
	GetPasswordReset(ctx context.Context, email, token string) (*models.PasswordReset, error)
	MarkPasswordResetAsUsed(ctx context.Context, id primitive.ObjectID) error
	DeleteExpiredPasswordResets(ctx context.Context) error

	// Token blacklist operations
	AddTokenToBlacklist(ctx context.Context, blacklist *models.TokenBlacklist) error
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)
	DeleteExpiredBlacklistedTokens(ctx context.Context) error
}

// MongoAuthRepository implements AuthRepository for MongoDB
type MongoAuthRepository struct {
	authUsersCollection      *mongo.Collection
	otpCollection            *mongo.Collection
	refreshTokensCollection  *mongo.Collection
	passwordResetsCollection *mongo.Collection
	blacklistCollection      *mongo.Collection
	client                   *mongo.Client
}

// NewMongoAuthRepository creates a new MongoDB auth repository
func NewMongoAuthRepository(mongoURL, databaseName string) *MongoAuthRepository {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURL))
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to MongoDB: %v", err))
	}

	// Test the connection
	if err := client.Ping(context.Background(), nil); err != nil {
		panic(fmt.Sprintf("Failed to ping MongoDB: %v", err))
	}

	db := client.Database(databaseName)

	repo := &MongoAuthRepository{
		authUsersCollection:      db.Collection("auth_users"),
		otpCollection:            db.Collection("otps"),
		refreshTokensCollection:  db.Collection("refresh_tokens"),
		passwordResetsCollection: db.Collection("password_resets"),
		blacklistCollection:      db.Collection("token_blacklist"),
		client:                   client,
	}

	// Create indexes
	repo.createIndexes()

	return repo
}

func (r *MongoAuthRepository) createIndexes() {
	ctx := context.Background()

	fmt.Println("🔍 Ensuring database indexes...")

	// Check existing indexes first
	indexView := r.authUsersCollection.Indexes()
	cursor, err := indexView.List(ctx)
	if err != nil {
		fmt.Printf("⚠️  Could not list existing indexes: %v\n", err)
	}

	existingIndexes := make(map[string]bool)
	if cursor != nil {
		var indexes []bson.M
		cursor.All(ctx, &indexes)
		cursor.Close(ctx)

		for _, index := range indexes {
			if indexName, ok := index["name"].(string); ok {
				existingIndexes[indexName] = true
				fmt.Printf("   Found existing index: %s\n", indexName)
			}
		}
	}

	// Create only missing essential indexes
	authUsersIndexes := []mongo.IndexModel{
		// Index on user_identifier
		{Keys: bson.D{{Key: "user_identifier", Value: 1}}, Options: options.Index().SetName("user_identifier_1")},
		// Unique index on email
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_1")},
	}

	indexesToCreate := []mongo.IndexModel{}
	expectedIndexes := map[string]mongo.IndexModel{
		"user_identifier_1": authUsersIndexes[0],
		"email_1":           authUsersIndexes[1],
	}

	for indexName, indexModel := range expectedIndexes {
		if !existingIndexes[indexName] {
			indexesToCreate = append(indexesToCreate, indexModel)
			fmt.Printf("   Will create missing index: %s\n", indexName)
		}
	}

	if len(indexesToCreate) > 0 {
		fmt.Println("🔨 Creating missing indexes...")
		result, err := r.authUsersCollection.Indexes().CreateMany(ctx, indexesToCreate)
		if err != nil {
			fmt.Printf("❌ Failed to create indexes: %v\n", err)
		} else {
			fmt.Printf("✅ Successfully created indexes: %v\n", result)
		}
	} else {
		fmt.Println("✅ All required indexes already exist")
	}

	fmt.Println("🔍 Index verification complete") // OTP indexes
	otpIndexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_identifier", Value: 1}, {Key: "otp", Value: 1}}}, // Updated field name
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
	r.otpCollection.Indexes().CreateMany(ctx, otpIndexes)

	// Refresh tokens indexes
	refreshTokenIndexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "user_identifier", Value: 1}}}, // Updated field name
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
	r.refreshTokensCollection.Indexes().CreateMany(ctx, refreshTokenIndexes)

	// Password resets indexes
	passwordResetIndexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "email", Value: 1}, {Key: "token", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
	r.passwordResetsCollection.Indexes().CreateMany(ctx, passwordResetIndexes)

	// Blacklist indexes
	blacklistIndexes := []mongo.IndexModel{
		{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	}
	r.blacklistCollection.Indexes().CreateMany(ctx, blacklistIndexes)
}

// CreateAuthUser creates a new auth user
func (r *MongoAuthRepository) CreateAuthUser(ctx context.Context, user *models.AuthUser) error {
	// Validate user data before insertion
	if user.UserID == "" {
		return fmt.Errorf("user_identifier cannot be empty")
	}
	if user.Email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	// Debug logging
	fmt.Printf("🔍 Repository: Creating user with ID: %s, UserID: %s, Email: %s\n", user.ID.Hex(), user.UserID, user.Email)

	// Convert to BSON to see exactly what MongoDB will receive
	bsonDoc, bsonErr := bson.Marshal(user)
	if bsonErr != nil {
		fmt.Printf("❌ Failed to marshal user to BSON: %v\n", bsonErr)
	} else {
		var docMap bson.M
		bson.Unmarshal(bsonDoc, &docMap)
		fmt.Printf("🔍 BSON Document being inserted: %+v\n", docMap)
	}

	_, err := r.authUsersCollection.InsertOne(ctx, user)
	if err != nil {
		fmt.Printf("❌ Repository: Failed to insert user: %v\n", err)

		// If it's a duplicate key error specifically for empty user_identifier, clean it up automatically
		if strings.Contains(err.Error(), "E11000") && strings.Contains(err.Error(), `user_identifier: ""`) {
			fmt.Println("🧹 Detected duplicate empty user_identifier, attempting cleanup...")

			// Try to delete documents with empty user_identifier
			deleteFilter := bson.M{"user_identifier": ""}
			deleteResult, deleteErr := r.authUsersCollection.DeleteMany(ctx, deleteFilter)
			if deleteErr != nil {
				fmt.Printf("❌ Failed to cleanup empty user_identifier documents: %v\n", deleteErr)
				return fmt.Errorf("database contains invalid records with empty user_identifier - manual cleanup required")
			}

			fmt.Printf("✅ Cleaned up %d documents with empty user_identifier\n", deleteResult.DeletedCount)

			// Try to insert again after cleanup
			_, retryErr := r.authUsersCollection.InsertOne(ctx, user)
			if retryErr != nil {
				fmt.Printf("❌ Retry failed after cleanup: %v\n", retryErr)
				return fmt.Errorf("failed to create user even after cleanup: %w", retryErr)
			} else {
				fmt.Printf("✅ Repository: User inserted successfully after cleanup\n")
				return nil
			}
		}

		return err
	} else {
		fmt.Printf("✅ Repository: User inserted successfully\n")
	}
	return nil
} // GetAuthUserByID retrieves an auth user by ID
func (r *MongoAuthRepository) GetAuthUserByID(ctx context.Context, userID string) (*models.AuthUser, error) {
	var user models.AuthUser
	filter := bson.M{"user_identifier": userID} // Updated field name

	err := r.authUsersCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

// GetAuthUserByEmail retrieves an auth user by email
func (r *MongoAuthRepository) GetAuthUserByEmail(ctx context.Context, email string) (*models.AuthUser, error) {
	var user models.AuthUser
	filter := bson.M{"email": email}

	err := r.authUsersCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

// UpdateAuthUser updates an auth user
func (r *MongoAuthRepository) UpdateAuthUser(ctx context.Context, user *models.AuthUser) error {
	user.UpdatedAt = time.Now()
	filter := bson.M{"user_identifier": user.UserID}
	update := bson.M{"$set": user}

	_, err := r.authUsersCollection.UpdateOne(ctx, filter, update)
	return err
}

// UpdatePasswordHash updates user password hash
func (r *MongoAuthRepository) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	filter := bson.M{"user_identifier": userID}
	update := bson.M{
		"$set": bson.M{
			"password_hash": passwordHash,
			"updated_at":    time.Now(),
		},
	}

	_, err := r.authUsersCollection.UpdateOne(ctx, filter, update)
	return err
}

// MarkUserAsVerified marks user as verified
func (r *MongoAuthRepository) MarkUserAsVerified(ctx context.Context, userID string) error {
	filter := bson.M{"user_identifier": userID}
	update := bson.M{
		"$set": bson.M{
			"is_verified": true,
			"updated_at":  time.Now(),
		},
	}

	_, err := r.authUsersCollection.UpdateOne(ctx, filter, update)
	return err
}

// CreateOTP creates a new OTP record
func (r *MongoAuthRepository) CreateOTP(ctx context.Context, otp *models.OTPRecord) error {
	otp.CreatedAt = time.Now()
	_, err := r.otpCollection.InsertOne(ctx, otp)
	return err
}

// GetOTP retrieves an OTP record
func (r *MongoAuthRepository) GetOTP(ctx context.Context, userID, otpCode string) (*models.OTPRecord, error) {
	var otp models.OTPRecord
	filter := bson.M{
		"user_identifier": userID,
		"otp":             otpCode,
		"is_used":         false,
		"expires_at":      bson.M{"$gt": time.Now()},
	}

	err := r.otpCollection.FindOne(ctx, filter).Decode(&otp)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &otp, nil
}

// MarkOTPAsUsed marks OTP as used
func (r *MongoAuthRepository) MarkOTPAsUsed(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"is_used": true}}

	_, err := r.otpCollection.UpdateOne(ctx, filter, update)
	return err
}

// DeleteExpiredOTPs deletes expired OTP records
func (r *MongoAuthRepository) DeleteExpiredOTPs(ctx context.Context) error {
	filter := bson.M{"expires_at": bson.M{"$lt": time.Now()}}
	_, err := r.otpCollection.DeleteMany(ctx, filter)
	return err
}

// CreateRefreshToken creates a new refresh token
func (r *MongoAuthRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	token.CreatedAt = time.Now()
	_, err := r.refreshTokensCollection.InsertOne(ctx, token)
	return err
}

// GetRefreshToken retrieves a refresh token
func (r *MongoAuthRepository) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	filter := bson.M{
		"token":      token,
		"is_revoked": false,
		"expires_at": bson.M{"$gt": time.Now()},
	}

	err := r.refreshTokensCollection.FindOne(ctx, filter).Decode(&refreshToken)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &refreshToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *MongoAuthRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	filter := bson.M{"token": token}
	update := bson.M{"$set": bson.M{"is_revoked": true}}

	_, err := r.refreshTokensCollection.UpdateOne(ctx, filter, update)
	return err
}

// RevokeAllUserTokens revokes all tokens for a user
func (r *MongoAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	filter := bson.M{"user_identifier": userID}
	update := bson.M{"$set": bson.M{"is_revoked": true}}

	_, err := r.refreshTokensCollection.UpdateMany(ctx, filter, update)
	return err
}

// DeleteExpiredTokens deletes expired refresh tokens
func (r *MongoAuthRepository) DeleteExpiredTokens(ctx context.Context) error {
	filter := bson.M{"expires_at": bson.M{"$lt": time.Now()}}
	_, err := r.refreshTokensCollection.DeleteMany(ctx, filter)
	return err
}

// CreatePasswordReset creates a password reset record
func (r *MongoAuthRepository) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	reset.CreatedAt = time.Now()
	_, err := r.passwordResetsCollection.InsertOne(ctx, reset)
	return err
}

// GetPasswordReset retrieves a password reset record
func (r *MongoAuthRepository) GetPasswordReset(ctx context.Context, email, token string) (*models.PasswordReset, error) {
	var reset models.PasswordReset
	filter := bson.M{
		"email":      email,
		"token":      token,
		"is_used":    false,
		"expires_at": bson.M{"$gt": time.Now()},
	}

	err := r.passwordResetsCollection.FindOne(ctx, filter).Decode(&reset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &reset, nil
}

// MarkPasswordResetAsUsed marks password reset as used
func (r *MongoAuthRepository) MarkPasswordResetAsUsed(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"is_used": true}}

	_, err := r.passwordResetsCollection.UpdateOne(ctx, filter, update)
	return err
}

// DeleteExpiredPasswordResets deletes expired password reset records
func (r *MongoAuthRepository) DeleteExpiredPasswordResets(ctx context.Context) error {
	filter := bson.M{"expires_at": bson.M{"$lt": time.Now()}}
	_, err := r.passwordResetsCollection.DeleteMany(ctx, filter)
	return err
}

// AddTokenToBlacklist adds a token to blacklist
func (r *MongoAuthRepository) AddTokenToBlacklist(ctx context.Context, blacklist *models.TokenBlacklist) error {
	blacklist.CreatedAt = time.Now()
	_, err := r.blacklistCollection.InsertOne(ctx, blacklist)
	return err
}

// IsTokenBlacklisted checks if token is blacklisted
func (r *MongoAuthRepository) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	filter := bson.M{
		"token":      token,
		"expires_at": bson.M{"$gt": time.Now()},
	}

	count, err := r.blacklistCollection.CountDocuments(ctx, filter)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// DeleteExpiredBlacklistedTokens deletes expired blacklisted tokens
func (r *MongoAuthRepository) DeleteExpiredBlacklistedTokens(ctx context.Context) error {
	filter := bson.M{"expires_at": bson.M{"$lt": time.Now()}}
	_, err := r.blacklistCollection.DeleteMany(ctx, filter)
	return err
}

// Close closes the MongoDB connection
func (r *MongoAuthRepository) Close(ctx context.Context) error {
	return r.client.Disconnect(ctx)
}
