// Package auth implements password hashing, tokens and the auth service.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16
	keyLen  = 32
	// Parsed hashes come from our own DB, but bound the cost anyway.
	maxMemoryKiB = 256 * 1024
)

// Hasher produces and verifies argon2id PHC strings. A semaphore bounds
// concurrent hashing so peak memory stays under the container limit.
type Hasher struct {
	memKiB  uint32
	time    uint32
	threads uint8
	sem     chan struct{}
	dummy   string
}

func NewHasher(memKiB, time uint32, threads uint8, concurrency int) (*Hasher, error) {
	h := &Hasher{memKiB: memKiB, time: time, threads: threads, sem: make(chan struct{}, concurrency)}
	d, err := h.Hash("dummy-password-for-timing")
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

// DefaultHasher uses m=32MiB, t=3, p=2 with at most 2 hashes in flight
// (~160ms on an M4; 64MiB doubled the time and the container memory need).
func DefaultHasher() (*Hasher, error) { return NewHasher(32*1024, 3, 2, 2) }

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := h.derive(password, salt, h.memKiB, h.time, h.threads)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.memKiB, h.time, h.threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify returns false for wrong passwords and for malformed hashes.
func (h *Hasher) Verify(password, encoded string) bool {
	mem, t, p, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false
	}
	got := h.derive(password, salt, mem, t, p)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VerifyDummy burns the same CPU as a real verification.
func (h *Hasher) VerifyDummy(password string) { h.Verify(password, h.dummy) }

func (h *Hasher) derive(password string, salt []byte, mem, t uint32, p uint8) []byte {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return argon2.IDKey([]byte(password), salt, t, mem, p, keyLen)
}

func parsePHC(s string) (mem, t uint32, p uint8, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("bad hash format")
	}
	var ver int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("bad hash version")
	}
	var p32 uint32
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p32); err != nil {
		return 0, 0, 0, nil, nil, errors.New("bad hash params")
	}
	if mem == 0 || mem > maxMemoryKiB || t == 0 || t > 20 || p32 == 0 || p32 > 255 {
		return 0, 0, 0, nil, nil, errors.New("hash params out of range")
	}
	p = uint8(p32)
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(salt) == 0 {
		return 0, 0, 0, nil, nil, errors.New("bad salt")
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(key) == 0 {
		return 0, 0, 0, nil, nil, errors.New("bad key")
	}
	return mem, t, p, salt, key, nil
}
