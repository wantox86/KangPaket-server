// Package config loads runtime configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
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
}

func Load() (*Config, error) {
	reg, err := strconv.ParseBool(getEnv("REGISTRATION_ENABLED", "false"))
	if err != nil {
		return nil, fmt.Errorf("invalid REGISTRATION_ENABLED: %w", err)
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
