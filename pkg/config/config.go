package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	// Database
	MongoURI     string
	DatabaseName string

	// JWT
	JWTSecret string

	// Server
	Environment string
	Host        string
	Port        string // Gateway port (alias for GatewayPort)

	// Service Ports
	AuthServicePort   string
	UserServicePort   string
	PostServicePort   string
	FollowServicePort string
	GatewayPort       string

	// Service URLs (for inter-service communication)
	AuthServiceURL   string
	UserServiceURL   string
	PostServiceURL   string
	FollowServiceURL string

	// Rate Limiting
	RateLimitRPS int

	// Email/SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPFromName string

	// OTP
	OTPLength        int
	OTPExpiryMinutes int

	// Tokens
	AccessTokenExpiryHours int
	RefreshTokenExpiryDays int

	// Development
	DevMode  bool
	LogLevel string

	// Security
	BcryptCost                    int
	MaxLoginAttempts              int
	AccountLockoutDurationMinutes int

	// CORS
	CORSAllowedOrigins []string
	CORSAllowedMethods []string
	CORSAllowedHeaders []string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found, using environment variables: %v", err)
	}

	config := &Config{
		// Database
		MongoURI:     getEnvOrDefault("MONGO_URI", "mongodb://localhost:27017/goblog"),
		DatabaseName: getEnvOrDefault("DATABASE_NAME", "goblog"),

		// JWT
		JWTSecret: getEnvOrDefault("JWT_SECRET", "your-super-secret-jwt-key-change-in-production-please"),

		// Server
		Environment: getEnvOrDefault("ENVIRONMENT", "development"),
		Host:        getEnvOrDefault("HOST", "0.0.0.0"),      // Bind to all interfaces by default
		Port:        getEnvOrDefault("GATEWAY_PORT", "8080"), // Alias for gateway port

		// Service Ports
		AuthServicePort:   getEnvOrDefault("AUTH_SERVICE_PORT", "50051"),
		UserServicePort:   getEnvOrDefault("USER_SERVICE_PORT", "50052"),
		PostServicePort:   getEnvOrDefault("POST_SERVICE_PORT", "50053"),
		FollowServicePort: getEnvOrDefault("FOLLOW_SERVICE_PORT", "50054"),
		GatewayPort:       getEnvOrDefault("GATEWAY_PORT", "8080"),

		// Service URLs (using localhost for local development)
		AuthServiceURL:   getEnvOrDefault("AUTH_SERVICE_URL", "localhost:50051"),
		UserServiceURL:   getEnvOrDefault("USER_SERVICE_URL", "localhost:50052"),
		PostServiceURL:   getEnvOrDefault("POST_SERVICE_URL", "localhost:50053"),
		FollowServiceURL: getEnvOrDefault("FOLLOW_SERVICE_URL", "localhost:50054"),

		// Rate Limiting
		RateLimitRPS: getEnvAsIntOrDefault("RATE_LIMIT_RPS", 10),

		// Email/SMTP
		SMTPHost:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnvAsIntOrDefault("SMTP_PORT", 587),
		SMTPUsername: getEnvOrDefault("SMTP_USERNAME", ""),
		SMTPPassword: getEnvOrDefault("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnvOrDefault("SMTP_FROM", ""),
		SMTPFromName: getEnvOrDefault("SMTP_FROM_NAME", "GoBlog Support"),

		// OTP
		OTPLength:        getEnvAsIntOrDefault("OTP_LENGTH", 6),
		OTPExpiryMinutes: getEnvAsIntOrDefault("OTP_EXPIRY_MINUTES", 15),

		// Tokens
		AccessTokenExpiryHours: getEnvAsIntOrDefault("ACCESS_TOKEN_EXPIRY_HOURS", 1),
		RefreshTokenExpiryDays: getEnvAsIntOrDefault("REFRESH_TOKEN_EXPIRY_DAYS", 7),

		// Development
		DevMode:  getEnvAsBoolOrDefault("DEV_MODE", true),
		LogLevel: getEnvOrDefault("LOG_LEVEL", "debug"),

		// Security
		BcryptCost:                    getEnvAsIntOrDefault("BCRYPT_COST", 12),
		MaxLoginAttempts:              getEnvAsIntOrDefault("MAX_LOGIN_ATTEMPTS", 5),
		AccountLockoutDurationMinutes: getEnvAsIntOrDefault("ACCOUNT_LOCKOUT_DURATION_MINUTES", 30),

		// CORS
		CORSAllowedOrigins: getEnvAsSliceOrDefault("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000", "http://localhost:8080"}),
		CORSAllowedMethods: getEnvAsSliceOrDefault("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
		CORSAllowedHeaders: getEnvAsSliceOrDefault("CORS_ALLOWED_HEADERS", []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"}),
	}

	// Validate required fields
	config.validate()

	return config
}

// validate checks that required configuration is present
func (c *Config) validate() {
	if c.JWTSecret == "your-super-secret-jwt-key-change-in-production-please" && c.Environment == "production" {
		log.Fatal("FATAL: JWT_SECRET must be changed for production environment")
	}

	if c.MongoURI == "" {
		log.Fatal("FATAL: MONGO_URI is required")
	}

	if c.Environment == "production" {
		if c.SMTPUsername == "" || c.SMTPPassword == "" {
			log.Fatal("FATAL: SMTP configuration is required for production")
		}
	}
}

// GetOTPExpiry returns OTP expiry duration
func (c *Config) GetOTPExpiry() time.Duration {
	return time.Duration(c.OTPExpiryMinutes) * time.Minute
}

// GetAccessTokenExpiry returns access token expiry duration
func (c *Config) GetAccessTokenExpiry() time.Duration {
	return time.Duration(c.AccessTokenExpiryHours) * time.Hour
}

// GetRefreshTokenExpiry returns refresh token expiry duration
func (c *Config) GetRefreshTokenExpiry() time.Duration {
	return time.Duration(c.RefreshTokenExpiryDays) * 24 * time.Hour
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsSliceOrDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
