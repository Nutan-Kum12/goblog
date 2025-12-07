package handlers

import (
	"context"
	"time"

	pb "github.com/Nutan-Kum12/goblog/proto/user"
	"github.com/Nutan-Kum12/goblog/services/user/internal/services"
)

// UserHandler implements the UserService gRPC service
type UserHandler struct {
	pb.UnimplementedUserServiceServer
	userService *services.UserService
}

// NewUserHandler creates a new instance of UserHandler
func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// CompleteProfile handles user profile completion
func (h *UserHandler) CompleteProfile(ctx context.Context, req *pb.CompleteProfileRequest) (*pb.CompleteProfileResponse, error) {
	var dateOfBirth *time.Time
	if req.DateOfBirth != nil {
		dob := req.DateOfBirth.AsTime()
		dateOfBirth = &dob
	}

	interests := services.ConvertInterestsFromProto(req.Interests)

	err := h.userService.CompleteProfile(ctx, req.UserId, req.FirstName, req.LastName, req.PhoneNumber, dateOfBirth, interests)
	if err != nil {
		return &pb.CompleteProfileResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.CompleteProfileResponse{
		Success: true,
		Message: "Profile completed successfully",
	}, nil
}

// GetUserProfile retrieves user profile
func (h *UserHandler) GetUserProfile(ctx context.Context, req *pb.GetUserProfileRequest) (*pb.GetUserProfileResponse, error) {
	user, err := h.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		return &pb.GetUserProfileResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	if user == nil {
		return &pb.GetUserProfileResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	return &pb.GetUserProfileResponse{
		Success:     true,
		Message:     "User profile retrieved successfully",
		UserProfile: user.ToProto(),
	}, nil
}

// UpdateUserProfile updates user profile
func (h *UserHandler) UpdateUserProfile(ctx context.Context, req *pb.UpdateUserProfileRequest) (*pb.UpdateUserProfileResponse, error) {
	var dateOfBirth *time.Time
	if req.DateOfBirth != nil {
		dob := req.DateOfBirth.AsTime()
		dateOfBirth = &dob
	}

	interests := services.ConvertInterestsFromProto(req.Interests)

	err := h.userService.UpdateProfile(ctx, req.UserId, req.FirstName, req.LastName, req.PhoneNumber, dateOfBirth, interests)
	if err != nil {
		return &pb.UpdateUserProfileResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.UpdateUserProfileResponse{
		Success: true,
		Message: "Profile updated successfully",
	}, nil
}

// GetUserByEmail retrieves user by email (internal service method)
func (h *UserHandler) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.GetUserByEmailResponse, error) {
	user, err := h.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return &pb.GetUserByEmailResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	if user == nil {
		return &pb.GetUserByEmailResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	return &pb.GetUserByEmailResponse{
		Success:     true,
		Message:     "User retrieved successfully",
		UserProfile: user.ToProto(),
	}, nil
}

// GetUserById retrieves user by ID (internal service method)
func (h *UserHandler) GetUserById(ctx context.Context, req *pb.GetUserByIdRequest) (*pb.GetUserByIdResponse, error) {
	user, err := h.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		return &pb.GetUserByIdResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	if user == nil {
		return &pb.GetUserByIdResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	return &pb.GetUserByIdResponse{
		Success:     true,
		Message:     "User retrieved successfully",
		UserProfile: user.ToProto(),
	}, nil
}

// UpdateVerificationStatus updates user verification status (internal service method)
func (h *UserHandler) UpdateVerificationStatus(ctx context.Context, req *pb.UpdateVerificationStatusRequest) (*pb.UpdateVerificationStatusResponse, error) {
	err := h.userService.UpdateVerificationStatus(ctx, req.UserId, req.IsVerified)
	if err != nil {
		return &pb.UpdateVerificationStatusResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.UpdateVerificationStatusResponse{
		Success: true,
		Message: "Verification status updated successfully",
	}, nil
}

// DeleteUser soft deletes a user
func (h *UserHandler) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	err := h.userService.DeleteUser(ctx, req.UserId)
	if err != nil {
		return &pb.DeleteUserResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.DeleteUserResponse{
		Success: true,
		Message: "User deleted successfully",
	}, nil
}

// ListUsers retrieves a paginated list of users (admin method)
func (h *UserHandler) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	users, totalCount, err := h.userService.ListUsers(ctx, int(req.Page), int(req.Limit), req.Search)
	if err != nil {
		return &pb.ListUsersResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	var protoUsers []*pb.UserProfile
	for _, user := range users {
		protoUsers = append(protoUsers, user.ToProto())
	}

	return &pb.ListUsersResponse{
		Success:    true,
		Message:    "Users retrieved successfully",
		Users:      protoUsers,
		TotalCount: int32(totalCount),
		Page:       req.Page,
		Limit:      req.Limit,
	}, nil
}
func (h *UserHandler) IncrementFollowerCount(ctx context.Context, req *pb.FollowerCountRequest) (*pb.UserCountUpdateResponse, error) {
	err := h.userService.IncrementFollowerCount(ctx, req.UserId)
	if err != nil {
		return &pb.UserCountUpdateResponse{
			Success: false,
			Message: "Failed to increment",
		}, err
	}
	return &pb.UserCountUpdateResponse{
		Success: true,
		Message: "Updated",
	}, nil
}
func (h *UserHandler) IncrementFollowingCount(ctx context.Context, req *pb.FollowerCountRequest) (*pb.UserCountUpdateResponse, error) {
	err := h.userService.IncrementFollowingCount(ctx, req.UserId)
	if err != nil {
		return &pb.UserCountUpdateResponse{
			Success: false,
			Message: "Failed to increment",
		}, err
	}
	return &pb.UserCountUpdateResponse{
		Success: true,
		Message: "Updated",
	}, nil
}

func (h *UserHandler) DecrementFollowerCount(ctx context.Context, req *pb.FollowerCountRequest) (*pb.UserCountUpdateResponse, error) {
	err := h.userService.DecrementFollowerCount(ctx, req.UserId)
	if err != nil {
		return &pb.UserCountUpdateResponse{
			Success: false,
			Message: "Failed to decrement",
		}, err
	}
	return &pb.UserCountUpdateResponse{
		Success: true,
		Message: "Updated",
	}, nil
}

func (h *UserHandler) DecrementFollowingCount(ctx context.Context, req *pb.FollowerCountRequest) (*pb.UserCountUpdateResponse, error) {
	err := h.userService.DecrementFollowingCount(ctx, req.UserId)
	if err != nil {
		return &pb.UserCountUpdateResponse{
			Success: false,
			Message: "Failed to decrement",
		}, err
	}
	return &pb.UserCountUpdateResponse{
		Success: true,
		Message: "Updated",
	}, nil
}
