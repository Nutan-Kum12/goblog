# GoBlog Microservices Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
AUTH_BINARY=auth
USER_BINARY=user
POST_BINARY=post
FOLLOW_BINARY=follow
GATEWAY_BINARY=gateway

# Directories
AUTH_DIR=./services/auth
USER_DIR=./services/user
POST_DIR=./services/post
FOLLOW_DIR=./services/follow
GATEWAY_DIR=./gateway
PROTO_DIR=./proto

# Protobuf generation
PROTOC=protoc
PROTOC_GEN_GO=$(shell go env GOPATH)/bin/protoc-gen-go
PROTOC_GEN_GO_GRPC=$(shell go env GOPATH)/bin/protoc-gen-go-grpc

.PHONY: all build clean test deps gen run-auth run-user run-gateway run-all help

# Default target
all: deps gen build

# Help target
help:
	@echo "Available targets:"
	@echo "  deps         - Download dependencies and install protobuf tools"
	@echo "  gen          - Generate protobuf Go code"
	@echo "  build        - Build all services"
	@echo "  test         - Run tests for all services"
	@echo "  run-auth     - Run auth service"
	@echo "  run-user     - Run user service"
	@echo "  run-gateway  - Run gateway service"
	@echo "  run-all      - Run all services concurrently (automatic)"
	@echo "  run-all-bg   - Run all services in background"
	@echo "  stop-all     - Stop all running services"
	@echo "  restart      - Restart all services"
	@echo "  dev          - Quick development start (build + run-all)"
	@echo "  run-all-simple    - Run services using PowerShell script (recommended)"
	@echo "  run-all-bg-simple - Run services in background using PowerShell script"
	@echo "  stop-all-simple   - Stop services using PowerShell script"
	@echo "  restart-simple    - Restart services using PowerShell script"
	@echo "  status            - Check service status"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"

# Install dependencies and protobuf tools
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	@echo "Installing protobuf tools..."
	$(GOGET) google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GOGET) google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate protobuf code
gen:
	@echo "Generating protobuf code..."
	@echo "Generating auth protobuf..."
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/auth/auth.proto
	@echo "Generating user protobuf..."
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/user/user.proto
	@echo "Generating post protobuf..."
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/post/post.proto
	@echo "Generating follow protobuf..."
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/follow/follow.proto	
	@echo "Protobuf generation completed!"		

# Build all services
build: build-auth build-user build-post build-follow build-gateway

build-auth:
	@echo "Building auth service..."
	$(GOBUILD) -o $(AUTH_BINARY) $(AUTH_DIR)

build-user:
	@echo "Building user service..."
	$(GOBUILD) -o $(USER_BINARY) $(USER_DIR)

build-post:
	@echo "Building post service..."
	$(GOBUILD) -o $(POST_BINARY) $(POST_DIR)

build-follow:
	@echo "Building follow service..."
	$(GOBUILD) -o $(FOLLOW_BINARY) $(FOLLOW_DIR)

build-gateway:
	@echo "Building gateway service..."
	$(GOBUILD) -o $(GATEWAY_BINARY) $(GATEWAY_DIR)

# Test all services
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(AUTH_BINARY) $(USER_BINARY) $(POST_BINARY) $(FOLLOW_BINARY) $(GATEWAY_BINARY)
	rm -f $(AUTH_BINARY).exe $(USER_BINARY).exe $(POST_BINARY).exe $(FOLLOW_BINARY).exe $(GATEWAY_BINARY).exe

# Run individual services
run-auth: build-auth
	@echo "Starting auth service on port 50051..."
	./$(AUTH_BINARY)

run-user: build-user
	@echo "Starting user service on port 50052..."
	./$(USER_BINARY)

run-post: build-post
	@echo "Starting post service on port 50053..."
	./$(POST_BINARY)

run-follow: build-follow
	@echo "Starting follow service on port 50054..."
	./$(FOLLOW_BINARY)

run-gateway: build-gateway
	@echo "Starting gateway on port 8080..."
	./$(GATEWAY_BINARY)

# Run all services concurrently
run-all: build
	@echo "Starting all services..."
	@echo "Auth Service starting on :50051"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/auth.exe' -WindowStyle Normal"
	@powershell -Command "Start-Sleep -Seconds 3"
	@echo "User Service starting on :50052"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/user.exe' -WindowStyle Normal"
	@powershell -Command "Start-Sleep -Seconds 3"
	@echo "Post Service starting on :50053"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/post.exe' -WindowStyle Normal"
	@powershell -Command "Start-Sleep -Seconds 3"
	@echo "Follow Service starting on :50054"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/follow.exe' -WindowStyle Normal"
	@powershell -Command "Start-Sleep -Seconds 3"
	@echo "Gateway starting on :8080"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/gateway.exe' -WindowStyle Normal"
	@echo "All services started! Gateway available at http://localhost:8080"
	@echo "Services are running in separate windows. Use 'make stop-all' to stop them."

# Run all services in background (minimized windows)
run-all-bg: build
	@echo "Starting all services in background..."
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/auth.exe' -WindowStyle Minimized"
	@powershell -Command "Start-Sleep -Seconds 3"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/user.exe' -WindowStyle Minimized"
	@powershell -Command "Start-Sleep -Seconds 3"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/post.exe' -WindowStyle Minimized"
	@powershell -Command "Start-Sleep -Seconds 3"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/follow.exe' -WindowStyle Minimized"
	@powershell -Command "Start-Sleep -Seconds 3"
	@powershell -Command "Start-Process -FilePath '$(CURDIR)/gateway.exe' -WindowStyle Minimized"
	@echo "All services running in background. Gateway at http://localhost:8080"
	@echo "Use 'make stop-all' to stop all services."

# Stop all services  
stop-all:
	@echo "Stopping all services..."
	@powershell -Command "Get-Process -Name 'auth' -ErrorAction SilentlyContinue | Stop-Process -Force"
	@powershell -Command "Get-Process -Name 'user' -ErrorAction SilentlyContinue | Stop-Process -Force"
	@powershell -Command "Get-Process -Name 'post' -ErrorAction SilentlyContinue | Stop-Process -Force"
	@powershell -Command "Get-Process -Name 'follow' -ErrorAction SilentlyContinue | Stop-Process -Force"
	@powershell -Command "Get-Process -Name 'gateway' -ErrorAction SilentlyContinue | Stop-Process -Force"
	@echo "All services stopped"

# Development workflow - build and run all
dev: run-all-simple

# Quick restart all services
restart: stop-all run-all

# Simple Windows-compatible run commands
run-all-simple: build
	@echo "Starting services with PowerShell script..."
	@powershell -ExecutionPolicy Bypass -File start-services.ps1

run-all-bg-simple: build  
	@echo "Starting services in background with PowerShell script..."
	@powershell -ExecutionPolicy Bypass -File start-services.ps1 -Background

stop-all-simple:
	@echo "Stopping services with PowerShell script..."
	@powershell -ExecutionPolicy Bypass -File start-services.ps1 -Action stop

status:
	@echo "Checking service status..."
	@powershell -ExecutionPolicy Bypass -File start-services.ps1 -Action status

restart-simple: 
	@echo "Restarting all services..."
	@powershell -ExecutionPolicy Bypass -File start-services.ps1 -Action restart

# Quick rebuild and run gateway (most common during development)
dev-gateway: build-gateway run-gateway

# Quick rebuild and run auth service
dev-auth: build-auth run-auth

# Quick rebuild and run user service
dev-user: build-user run-user

# Format Go code
fmt:
	@echo "Formatting Go code..."
	$(GOCMD) fmt ./...

# Lint Go code (requires golangci-lint)
lint:
	@echo "Linting Go code..."
	golangci-lint run ./...

# Check for security issues (requires gosec)
security:
	@echo "Checking for security issues..."
	gosec ./...

# View service logs (placeholder - implement with your logging solution)
logs:
	@echo "Use docker logs or your logging solution to view service logs"

# Database setup (placeholder - customize for your MongoDB setup)
db-setup:
	@echo "Setting up MongoDB..."
	@echo "Ensure MongoDB is running on mongodb://localhost:27017"

# Docker commands
docker-build:
	@echo "Building Docker images..."
	docker-compose build

docker-up: docker-build
	@echo "Starting all services with Docker..."
	docker-compose up -d
	@echo "All services running in Docker. Gateway at http://localhost:8080"

docker-down:
	@echo "Stopping Docker services..."
	docker-compose down

docker-logs:
	@echo "Showing Docker service logs..."
	docker-compose logs -f

docker-restart: docker-down docker-up

# Production deployment helpers
deploy-prod:
	@echo "Deploying to production..."
	@echo "Make sure to set production environment variables first!"
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Database management
db-reset:
	@echo "Resetting database..."
	docker-compose down -v
	docker-compose up -d mongodb
	@echo "Database reset complete"