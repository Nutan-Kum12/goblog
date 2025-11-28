package models

import (
	"time"

	pb "github.com/Nutan-Kum12/goblog/proto/user"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// User represents a user in MongoDB
type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID         string             `bson:"user_id" json:"user_id"`
	Email          string             `bson:"email" json:"email"`
	FirstName      string             `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName       string             `bson:"last_name,omitempty" json:"last_name,omitempty"`
	PhoneNumber    string             `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	DateOfBirth    *time.Time         `bson:"date_of_birth,omitempty" json:"date_of_birth,omitempty"`
	Interests      []string           `bson:"interests,omitempty" json:"interests,omitempty"`
	IsVerified     bool               `bson:"is_verified" json:"is_verified"`
	FollowersCount int32              `bson:"followers_count" json:"followers_count"`
	FollowingCount int32              `bson:"following_count" json:"following_count"`
	IsActive       bool               `bson:"is_active" json:"is_active"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

// ToProto converts User model to protobuf UserProfile
func (u *User) ToProto() *pb.UserProfile {
	userProfile := &pb.UserProfile{
		UserId:         u.UserID,
		Email:          u.Email,
		FirstName:      u.FirstName,
		LastName:       u.LastName,
		PhoneNumber:    u.PhoneNumber,
		IsVerified:     u.IsVerified,
		IsActive:       u.IsActive,
		FollowersCount: u.FollowersCount,
		FollowingCount: u.FollowingCount,
	}

	// Convert created_at and updated_at
	if !u.CreatedAt.IsZero() {
		userProfile.CreatedAt = timestamppb.New(u.CreatedAt)
	}
	if !u.UpdatedAt.IsZero() {
		userProfile.UpdatedAt = timestamppb.New(u.UpdatedAt)
	}

	// Convert date of birth
	if u.DateOfBirth != nil {
		userProfile.DateOfBirth = timestamppb.New(*u.DateOfBirth)
	}

	// Convert interests
	for _, interest := range u.Interests {
		if category, ok := pb.InterestCategory_value[interest]; ok {
			userProfile.Interests = append(userProfile.Interests, pb.InterestCategory(category))
		}
	}

	return userProfile
}

// FromProto creates User model from protobuf data
// func FromProto(userProfile *pb.UserProfile) *User {
// 	user := &User{
// 		UserID:         userProfile.UserId,
// 		Email:          userProfile.Email,
// 		FirstName:      userProfile.FirstName,
// 		LastName:       userProfile.LastName,
// 		PhoneNumber:    userProfile.PhoneNumber,
// 		IsVerified:     userProfile.IsVerified,
// 		IsActive:       userProfile.IsActive,
// 		FollowersCount: userProfile.FollowersCount,
// 		FollowingCount: userProfile.FollowingCount,
// 	}

// 	// Convert timestamps
// 	if userProfile.CreatedAt != nil {
// 		user.CreatedAt = userProfile.CreatedAt.AsTime()
// 	}
// 	if userProfile.UpdatedAt != nil {
// 		user.UpdatedAt = userProfile.UpdatedAt.AsTime()
// 	}
// 	if userProfile.DateOfBirth != nil {
// 		dob := userProfile.DateOfBirth.AsTime()
// 		user.DateOfBirth = &dob
// 	}

// 	// Convert interests
// 	for _, interest := range userProfile.Interests {
// 		user.Interests = append(user.Interests, interest.String())
// 	}

// 	return user
// }
