package repository

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/Nutan-Kum12/goblog/services/user/internal/models"
)

// UserRepository defines the interface for user database operations
type UserRepository interface {
	// User operation
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, userID string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserProfile(ctx context.Context, userID string, firstName, lastName, phoneNumber string, dateOfBirth *time.Time, interests []string) error
	UpdateVerificationStatus(ctx context.Context, userID string, isVerified bool) error
	UpdateUserEmail(ctx context.Context, userID string, email string) error
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, page, limit int, search string) ([]*models.User, int64, error)
	IncrementFollowerCount(ctx context.Context, userID string) error
	DecrementFollowerCount(ctx context.Context, userID string) error
	IncrementFollowingCount(ctx context.Context, userID string) error
	DecrementFollowingCount(ctx context.Context, userID string) error
}

// MongoUserRepository implements UserRepository for MongoDB
type MongoUserRepository struct {
	collection *mongo.Collection
	client     *mongo.Client
}

// NewMongoUserRepository creates a new MongoDB user repository
func NewMongoUserRepository(mongoURL, databaseName string) *MongoUserRepository {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURL))
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to MongoDB: %v", err))
	}

	// Test the connection
	if err := client.Ping(context.Background(), nil); err != nil {
		panic(fmt.Sprintf("Failed to ping MongoDB: %v", err))
	}

	collection := client.Database(databaseName).Collection("users")

	// Create indexes
	indexModel := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	_, err = collection.Indexes().CreateMany(context.Background(), indexModel)
	if err != nil {
		panic(fmt.Sprintf("Failed to create indexes: %v", err))
	}

	return &MongoUserRepository{
		collection: collection,
		client:     client,
	}
}

// CreateUser creates a new user in the database
func (r *MongoUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	log.Printf("🔧 Repository: Creating user in database - UserID: %s, Email: %s", user.UserID, user.Email)

	result, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		log.Printf("❌ Repository: Failed to insert user: %v", err)
		return err
	}

	log.Printf("✅ Repository: User inserted successfully with MongoDB ID: %v", result.InsertedID)
	return nil
}

// GetUserByID retrieves a user by their ID
func (r *MongoUserRepository) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	var user models.User
	filter := bson.M{"user_id": userID}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by their email
func (r *MongoUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{"email": email}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (r *MongoUserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()

	filter := bson.M{"user_id": user.UserID}
	update := bson.M{"$set": user}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// UpdateUserProfile updates user profile information
func (r *MongoUserRepository) UpdateUserProfile(ctx context.Context, userID string, firstName, lastName, phoneNumber string, dateOfBirth *time.Time, interests []string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{
		"$set": bson.M{
			"first_name":    firstName,
			"last_name":     lastName,
			"phone_number":  phoneNumber,
			"date_of_birth": dateOfBirth,
			"interests":     interests,
			"updated_at":    time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// UpdateVerificationStatus updates the verification status of a user
func (r *MongoUserRepository) UpdateVerificationStatus(ctx context.Context, userID string, isVerified bool) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_verified": isVerified,
			"updated_at":  time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// UpdateUserEmail updates the email field of a user
func (r *MongoUserRepository) UpdateUserEmail(ctx context.Context, userID string, email string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{
		"$set": bson.M{
			"email":      email,
			"updated_at": time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// DeleteUser soft deletes a user by setting is_active to false
func (r *MongoUserRepository) DeleteUser(ctx context.Context, userID string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_active":  false,
			"updated_at": time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// ListUsers retrieves a paginated list of users
func (r *MongoUserRepository) ListUsers(ctx context.Context, page, limit int, search string) ([]*models.User, int64, error) {
	filter := bson.M{"is_active": true}

	if search != "" {
		filter["$or"] = []bson.M{
			{"first_name": primitive.Regex{Pattern: search, Options: "i"}},
			{"last_name": primitive.Regex{Pattern: search, Options: "i"}},
			{"email": primitive.Regex{Pattern: search, Options: "i"}},
		}
	}

	// Count total documents
	totalCount, err := r.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// Calculate skip
	skip := (page - 1) * limit

	// Find documents with pagination
	findOptions := options.Find()
	findOptions.SetLimit(int64(limit))
	findOptions.SetSkip(int64(skip))
	findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := r.collection.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, 0, err
	}

	return users, totalCount, nil
}

func (r *MongoUserRepository) IncrementFollowerCount(ctx context.Context, userID string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{"$inc": bson.M{"followers_count": 1}}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

func (r *MongoUserRepository) DecrementFollowerCount(ctx context.Context, userID string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{"$inc": bson.M{"followers_count": -1}}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

func (r *MongoUserRepository) IncrementFollowingCount(ctx context.Context, userID string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{"$inc": bson.M{"following_count": 1}}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

func (r *MongoUserRepository) DecrementFollowingCount(ctx context.Context, userID string) error {
	filter := bson.M{"user_id": userID}
	update := bson.M{"$inc": bson.M{"following_count": -1}}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// GetDatabase returns the MongoDB database instance
func (r *MongoUserRepository) GetDatabase() *mongo.Database {
	return r.collection.Database()
}

// Close closes the MongoDB connection
func (r *MongoUserRepository) Close(ctx context.Context) error {
	return r.client.Disconnect(ctx)
}
