// Package config loads runtime configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const minJWTSecretLen = 32

type Config struct {
	Port                string
	DBHost              string
	DBPort              string
	DBName              string
	DBUser              string
	DBPassword          string
	JWTSecret           string
	RegistrationEnabled bool
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	TrustProxyHeaders   bool
	CORSAllowedOrigins  []string
	RateLimitPerMin     int
	RateLimitUserPerMin int
}

func Load() (*Config, error) {
	reg, err := strconv.ParseBool(getEnv("REGISTRATION_ENABLED", "false"))
	if err != nil {
		return nil, fmt.Errorf("invalid REGISTRATION_ENABLED: %w", err)
	}

	trust, err := strconv.ParseBool(getEnv("TRUST_PROXY_HEADERS", "false"))
	if err != nil {
		return nil, fmt.Errorf("invalid TRUST_PROXY_HEADERS: %w", err)
	}
	accessTTL, err := time.ParseDuration(getEnv("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid ACCESS_TOKEN_TTL: %w", err)
	}
	refreshTTL, err := time.ParseDuration(getEnv("REFRESH_TOKEN_TTL", "720h"))
	if err != nil {
		return nil, fmt.Errorf("invalid REFRESH_TOKEN_TTL: %w", err)
	}
	perMin, err := strconv.Atoi(getEnv("RATE_LIMIT_PER_MIN", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_PER_MIN: %w", err)
	}
	userPerMin, err := strconv.Atoi(getEnv("RATE_LIMIT_USER_PER_MIN", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_USER_PER_MIN: %w", err)
	}
	var origins []string
	for _, o := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}

	cfg := &Config{
		Port:                getEnv("PORT", "8080"),
		DBHost:              getEnv("DB_HOST", "127.0.0.1"),
		DBPort:              getEnv("DB_PORT", "3306"),
		DBName:              getEnv("DB_NAME", "kangpaket"),
		DBUser:              getEnv("DB_USER", "kangpaket"),
		DBPassword:          os.Getenv("DB_PASSWORD"),
		JWTSecret:           os.Getenv("JWT_SECRET"),
		RegistrationEnabled: reg,
		AccessTokenTTL:      accessTTL,
		RefreshTokenTTL:     refreshTTL,
		TrustProxyHeaders:   trust,
		CORSAllowedOrigins:  origins,
		RateLimitPerMin:     perMin,
		RateLimitUserPerMin: userPerMin,
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.DBPassword == "" {
		return errors.New("DB_PASSWORD is required")
	}
	if len(c.JWTSecret) < minJWTSecretLen {
		return fmt.Errorf("JWT_SECRET is required and must be at least %d characters", minJWTSecretLen)
	}
	if strings.HasPrefix(strings.ToLower(c.JWTSecret), "change-me") {
		return errors.New("JWT_SECRET is still the placeholder value; generate a random one")
	}
	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return errors.New("ACCESS_TOKEN_TTL and REFRESH_TOKEN_TTL must be positive")
	}
	if c.RateLimitPerMin < 1 || c.RateLimitUserPerMin < 1 {
		return errors.New("rate limits must be at least 1 per minute")
	}
	return nil
}

// DSN returns the MySQL DSN; the password is never logged.
func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC&time_zone=%s",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, url.QueryEscape("'+00:00'"))
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
