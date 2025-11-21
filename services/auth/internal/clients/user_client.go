package clients

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	pb "github.com/Nutan-Kum12/goblog/proto/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// UserServiceClient wraps the gRPC user service client
type UserServiceClient struct {
	client     pb.UserServiceClient
	conn       *grpc.ClientConn
	serviceURL string
	mu         sync.RWMutex
	connected  bool
}

// NewUserServiceClient creates a new user service client with lazy connection
func NewUserServiceClient(serviceURL string) (*UserServiceClient, error) {
	client := &UserServiceClient{
		serviceURL: serviceURL,
		connected:  false,
	}

	// Try to establish initial connection
	err := client.connect()
	if err != nil {
		log.Printf("Warning: Initial connection to user service failed: %v. Will retry on first request.", err)
		// Don't return error, allow lazy connection
	}

	return client, nil
}

// connect establishes connection to the user service
func (c *UserServiceClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.serviceURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to user service at %s: %w", c.serviceURL, err)
	}

	c.client = pb.NewUserServiceClient(conn)
	c.conn = conn
	c.connected = true

	log.Printf("Successfully connected to user service at %s", c.serviceURL)
	return nil
}

// ensureConnection ensures we have a valid connection, with retry logic
func (c *UserServiceClient) ensureConnection() error {
	c.mu.RLock()
	if c.connected {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	// Try to connect with retries
	var lastErr error
	for i := 0; i < 3; i++ {
		if err := c.connect(); err != nil {
			lastErr = err
			log.Printf("Connection attempt %d failed: %v", i+1, err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
		return nil
	}

	return fmt.Errorf("failed to establish connection after retries: %w", lastErr)
}

// Close closes the gRPC connection
func (c *UserServiceClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.connected = false
		return err
	}
	return nil
}

// withConnection wraps gRPC calls with connection handling
func (c *UserServiceClient) withConnection(fn func() error) error {
	if err := c.ensureConnection(); err != nil {
		return fmt.Errorf("user service unavailable: %w", err)
	}

	return fn()
}

// GetUserProfile gets a user profile by user ID
func (c *UserServiceClient) GetUserProfile(ctx context.Context, userID string) (*pb.GetUserProfileResponse, error) {
	var resp *pb.GetUserProfileResponse
	err := c.withConnection(func() error {
		req := &pb.GetUserProfileRequest{
			UserId: userID,
		}
		var err error
		resp, err = c.client.GetUserProfile(ctx, req)
		return err
	})
	return resp, err
}

// CompleteUserProfile completes a user profile
func (c *UserServiceClient) CompleteUserProfile(ctx context.Context, req *pb.CompleteProfileRequest) (*pb.CompleteProfileResponse, error) {
	var resp *pb.CompleteProfileResponse
	err := c.withConnection(func() error {
		var err error
		resp, err = c.client.CompleteProfile(ctx, req)
		return err
	})
	return resp, err
}

// // UpdateUserProfile updates a user profile
func (c *UserServiceClient) UpdateUserProfile(ctx context.Context, req *pb.UpdateUserProfileRequest) (*pb.UpdateUserProfileResponse, error) {
	var resp *pb.UpdateUserProfileResponse
	err := c.withConnection(func() error {
		var err error
		resp, err = c.client.UpdateUserProfile(ctx, req)
		return err
	})
	return resp, err
}

// DeleteUserAccount deletes a user account
func (c *UserServiceClient) DeleteUserAccount(ctx context.Context, userID string) (*pb.DeleteUserResponse, error) {
	var resp *pb.DeleteUserResponse
	err := c.withConnection(func() error {
		req := &pb.DeleteUserRequest{
			UserId: userID,
		}
		var err error
		resp, err = c.client.DeleteUser(ctx, req)
		return err
	})
	return resp, err
}

// // ListUsers lists users (admin method)
func (c *UserServiceClient) ListUsers(ctx context.Context, page, limit int32, search string) (*pb.ListUsersResponse, error) {
	var resp *pb.ListUsersResponse
	err := c.withConnection(func() error {
		req := &pb.ListUsersRequest{
			Page:   page,
			Limit:  limit,
			Search: search,
		}
		var err error
		resp, err = c.client.ListUsers(ctx, req)
		return err
	})
	return resp, err
}

// // GetUserById gets a user by ID
func (c *UserServiceClient) GetUserById(ctx context.Context, userID string) (*pb.GetUserByIdResponse, error) {
	var resp *pb.GetUserByIdResponse
	err := c.withConnection(func() error {
		req := &pb.GetUserByIdRequest{
			UserId: userID,
		}
		var err error
		resp, err = c.client.GetUserById(ctx, req)
		return err
	})
	return resp, err
}

// // GetUserByEmail gets a user by email
// func (c *UserServiceClient) GetUserByEmail(ctx context.Context, email string) (*pb.GetUserByEmailResponse, error) {
// 	var resp *pb.GetUserByEmailResponse
// 	err := c.withConnection(func() error {
// 		req := &pb.GetUserByEmailRequest{
// 			Email: email,
// 		}
// 		var err error
// 		resp, err = c.client.GetUserByEmail(ctx, req)
// 		return err
// 	})
// 	return resp, err
// }

// UpdateVerificationStatus updates user verification status
func (c *UserServiceClient) UpdateVerificationStatus(ctx context.Context, userID string, isVerified bool) (*pb.UpdateVerificationStatusResponse, error) {
	var resp *pb.UpdateVerificationStatusResponse
	err := c.withConnection(func() error {
		req := &pb.UpdateVerificationStatusRequest{
			UserId:     userID,
			IsVerified: isVerified,
		}
		var err error
		resp, err = c.client.UpdateVerificationStatus(ctx, req)
		return err
	})
	return resp, err
}
