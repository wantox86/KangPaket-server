package config

import (
	"strings"
	"testing"
)

func setValid(t *testing.T) {
	t.Helper()
	t.Setenv("DB_PASSWORD", "pw")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 48))
}

func TestLoadDefaults(t *testing.T) {
	setValid(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" || cfg.RegistrationEnabled {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsBadJWTSecret(t *testing.T) {
	for _, s := range []string{"", "short"} {
		setValid(t)
		t.Setenv("JWT_SECRET", s)
		if _, err := Load(); err == nil {
			t.Fatalf("expected error for JWT_SECRET=%q", s)
		}
	}
}

func TestLoadRequiresDBPassword(t *testing.T) {
	setValid(t)
	t.Setenv("DB_PASSWORD", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error")
	}
}
