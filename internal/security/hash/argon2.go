package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

func DefaultArgon2() *Argon2Hasher {
	return &Argon2Hasher{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

func NewArgon2(memory, iterations uint32, parallelism uint8, saltLen, keyLen uint32) *Argon2Hasher {
	return &Argon2Hasher{
		Time:    iterations,
		Memory:  memory,
		Threads: parallelism,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
}

func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: salt generation: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("%d:%d:%d:%s:%s", h.Time, h.Memory, h.Threads, b64Salt, b64Hash), nil
}

func (h *Argon2Hasher) Verify(password, encodedHash string) error {
	parts := strings.Split(encodedHash, ":")
	if len(parts) != 5 {
		return fmt.Errorf("argon2: invalid hash format")
	}

	time, memory, threads := h.Time, h.Memory, h.Threads
	if _, err := fmt.Sscanf(strings.Join(parts[:3], ":"), "%d:%d:%d", &time, &memory, &threads); err != nil {
		return fmt.Errorf("argon2: parse parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("argon2: decode salt: %w", err)
	}
	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("argon2: decode hash: %w", err)
	}

	computed := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), uint32(len(hashBytes)))
	if subtle.ConstantTimeCompare(hashBytes, computed) == 1 {
		return nil
	}
	return fmt.Errorf("invalid password")
}
