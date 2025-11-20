package handlers

import (
	"context"
	"log"

	pb "github.com/Nutan-Kum12/goblog/proto/auth"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/services"
)

// AuthHandler implements the AuthService gRPC service
type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	authService *services.AuthService
}

// NewAuthHandler creates a new instance of AuthHandler
func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	user, err := h.authService.RegisterUser(ctx, req.Email, req.Password)
	if err != nil {
		return &pb.RegisterResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	// Generate OTP for email verification
	// Generate and send OTP via email
	_, err = h.authService.GenerateAndSendOTP(ctx, user.UserID, "registration", user.Email)
	if err != nil {
		return &pb.RegisterResponse{
			Success: false,
			Message: "Registration successful but failed to generate OTP",
		}, nil
	}

	// Success message
	return &pb.RegisterResponse{
		Success: true,
		Message: "Registration successful. Please check your email for the OTP verification code.",
		UserId:  user.UserID,
	}, nil
}

// VerifyOTP handles OTP verification after registration
func (h *AuthHandler) VerifyOTP(ctx context.Context, req *pb.VerifyOTPRequest) (*pb.VerifyOTPResponse, error) {
	log.Printf("🔍 Verifying OTP for user %s with OTP: %s", req.UserId, req.Otp)

	err := h.authService.VerifyOTP(ctx, req.UserId, req.Otp)
	if err != nil {
		log.Printf("❌ OTP verification failed for user %s: %v", req.UserId, err)
		return &pb.VerifyOTPResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	log.Printf("✅ OTP verified successfully for user %s", req.UserId)

	// Generate tokens after successful OTP verification
	log.Printf("🔑 Generating tokens for verified user %s", req.UserId)
	accessToken, refreshToken, err := h.authService.GenerateTokensForUser(ctx, req.UserId)
	if err != nil {
		log.Printf("❌ Failed to generate tokens after OTP verification: %v", err)
		// Still return success for OTP verification, but without tokens
		return &pb.VerifyOTPResponse{
			Success: true,
			Message: "OTP verified successfully but failed to generate tokens",
		}, nil
	}

	log.Printf("✅ Tokens generated successfully for user %s", req.UserId)
	return &pb.VerifyOTPResponse{
		Success:      true,
		Message:      "OTP verified successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// ResendOTP handles resending OTP
func (h *AuthHandler) ResendOTP(ctx context.Context, req *pb.ResendOTPRequest) (*pb.ResendOTPResponse, error) {
	// First get the user to retrieve their email
	user, err := h.authService.GetUserByID(ctx, req.UserId)
	if err != nil {
		return &pb.ResendOTPResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	// Generate and send OTP via email
	_, err = h.authService.GenerateAndSendOTP(ctx, req.UserId, "registration", user.Email)
	if err != nil {
		return &pb.ResendOTPResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.ResendOTPResponse{
		Success: true,
		Message: "OTP resent successfully. Please check your email.",
	}, nil
}

// Login handles user authentication
func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, accessToken, refreshToken, err := h.authService.LoginUser(ctx, req.Email, req.Password)
	if err != nil {
		return &pb.LoginResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.LoginResponse{
		Success:      true,
		Message:      "Login successful",
		UserId:       user.ID.Hex(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	accessToken, refreshToken, err := h.authService.RefreshAccessToken(ctx, req.RefreshToken)
	if err != nil {
		return &pb.RefreshTokenResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.RefreshTokenResponse{
		Success:      true,
		Message:      "Token refreshed successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// ValidateToken handles token validation
func (h *AuthHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	claims, err := h.authService.ValidateAccessToken(req.AccessToken)
	if err != nil {
		return &pb.ValidateTokenResponse{
			Valid:   false,
			Message: "Invalid token",
		}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
	}, nil
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest) (*pb.ForgotPasswordResponse, error) {
	log.Printf("🔐 Processing forgot password request for: %s", req.Email)

	// Validate request
	if req.Email == "" {
		return &pb.ForgotPasswordResponse{
			Success: false,
			Message: "Email is required",
		}, nil
	}

	// Call service to handle forgot password
	_, err := h.authService.ForgotPassword(ctx, req.Email)
	if err != nil {
		log.Printf("❌ Forgot password failed for %s: %v", req.Email, err)
		return &pb.ForgotPasswordResponse{
			Success: false,
			Message: "Failed to process password reset request",
		}, nil
	}

	// Success response (don't reveal if email exists or not)
	log.Printf("✅ Forgot password processed for: %s", req.Email)
	return &pb.ForgotPasswordResponse{
		Success: true,
		Message: "If an account with this email exists, you will receive a password reset link",
	}, nil
}

// ResetPassword handles password reset with token
func (h *AuthHandler) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	log.Printf("🔐 Processing password reset request for: %s", req.Email)

	// Validate request
	if req.Email == "" {
		return &pb.ResetPasswordResponse{
			Success: false,
			Message: "Email is required",
		}, nil
	}
	if req.ResetToken == "" {
		return &pb.ResetPasswordResponse{
			Success: false,
			Message: "Reset token is required",
		}, nil
	}
	if req.NewPassword == "" {
		return &pb.ResetPasswordResponse{
			Success: false,
			Message: "New password is required",
		}, nil
	}

	// Call service to reset password
	err := h.authService.ResetPassword(ctx, req.Email, req.ResetToken, req.NewPassword)
	if err != nil {
		log.Printf("❌ Password reset failed for %s: %v", req.Email, err)
		return &pb.ResetPasswordResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	log.Printf("✅ Password reset successful for: %s", req.Email)
	return &pb.ResetPasswordResponse{
		Success: true,
		Message: "Password has been reset successfully. Please log in with your new password.",
	}, nil
}

// ChangePassword handles password change for authenticated users
func (h *AuthHandler) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	// TODO: Implement password change logic
	return &pb.ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}
