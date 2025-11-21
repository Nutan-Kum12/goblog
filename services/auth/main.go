package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/Nutan-Kum12/goblog/pkg/config"
	"github.com/Nutan-Kum12/goblog/pkg/email"
	pb "github.com/Nutan-Kum12/goblog/proto/auth"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/clients"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/handlers"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/repository"
	"github.com/Nutan-Kum12/goblog/services/auth/internal/services"
	"google.golang.org/grpc"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize MongoDB repository
	authRepo := repository.NewMongoAuthRepository(cfg.MongoURI, cfg.DatabaseName)
	defer func() {
		if err := authRepo.Close(context.Background()); err != nil {
			log.Printf("Error closing MongoDB connection: %v", err)
		}
	}()

	// Initialize email service
	emailService := email.NewEmailService(cfg)

	// Initialize user service client for inter-service communication
	userClient, err := clients.NewUserServiceClient(cfg.UserServiceURL)
	if err != nil {
		log.Printf("Warning: Failed to connect to user service: %v", err)
		userClient = nil // Continue without user service connection
	} else {
		defer func() {
			if err := userClient.Close(); err != nil {
				log.Printf("Error closing user service connection: %v", err)
			}
		}()
		log.Printf("Connected to user service at %s", cfg.UserServiceURL)
	}

	// Initialize service layer with user client and email service
	authService := services.NewAuthServiceWithEmailAndClients(authRepo, cfg.JWTSecret, emailService, userClient)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Create a TCP listener
	address := fmt.Sprintf("%s:%s", cfg.Host, cfg.AuthServicePort)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", address, err)
	}

	// Create a new gRPC server
	s := grpc.NewServer()

	// Register the auth service
	pb.RegisterAuthServiceServer(s, authHandler)

	log.Printf("Auth service starting on %s (environment: %s)...", address, cfg.Environment)

	// Start the server
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
