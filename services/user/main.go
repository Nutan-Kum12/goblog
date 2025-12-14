package main

import (
	"fmt"
	"log"
	"net"

	"github.com/Nutan-Kum12/goblog/pkg/config"
	pb "github.com/Nutan-Kum12/goblog/proto/user"
	"github.com/Nutan-Kum12/goblog/services/user/internal/clients"
	"github.com/Nutan-Kum12/goblog/services/user/internal/handlers"
	"github.com/Nutan-Kum12/goblog/services/user/internal/repository"
	"github.com/Nutan-Kum12/goblog/services/user/internal/services"
	"google.golang.org/grpc"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize repository
	userRepo := repository.NewMongoUserRepository(cfg.MongoURI, cfg.DatabaseName)

	// Initialize auth service client for inter-service communication
	authClient, err := clients.NewAuthServiceClient(cfg.AuthServiceURL)
	if err != nil {
		log.Printf("Warning: Failed to connect to auth service: %v", err)
		authClient = nil // Continue without auth service connection
	} else {
		defer func() {
			if err := authClient.Close(); err != nil {
				log.Printf("Error closing auth service connection: %v", err)
			}
		}()
		log.Printf("Connected to auth service at %s", cfg.AuthServiceURL)
	}

	// Initialize service layer with auth client
	userService := services.NewUserServiceWithClients(userRepo, authClient)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)

	// Create a TCP listener
	address := fmt.Sprintf("%s:%s", cfg.Host, cfg.UserServicePort)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", address, err)
	}

	// Create a new gRPC server
	s := grpc.NewServer()

	// Register the user service
	pb.RegisterUserServiceServer(s, userHandler)

	log.Printf("User service starting on %s (environment: %s)...", address, cfg.Environment)

	// Start the server
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
