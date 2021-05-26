package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

type Config struct {
	Hash    string `json:"hash,omitempty"`
	Salt    string `json:"salt,omitempty"`
	Memory  uint32 `json:"memory,omitempty"`
	Time    uint32 `json:"time,omitempty"`
	Threads uint8  `json:"threads,omitempty"`
	Length  uint32 `json:"length,omitempty"`
}

func NewPassword(password string) (config *Config, err error) {
	config = &Config{
		Memory:  32 * 1024,
		Time:    3,
		Threads: 2,
		Length:  32,
	}
	salt, err := generateRandomBytes(24)
	if err != nil {
		return nil, err
	}
	config.Salt = base64.RawStdEncoding.EncodeToString(salt)
	result := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.Length)
	config.Hash = base64.RawStdEncoding.EncodeToString(result)
	return config, nil
}
func ValidatePassword(password string, config *Config) (match bool, err error) {
	salt, err := base64.RawStdEncoding.DecodeString(config.Salt)
	if err != nil {
		return false, err
	}
	hash, err := base64.RawStdEncoding.DecodeString(config.Hash)
	if err != nil {
		return false, err
	}
	result := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.Length)
	if subtle.ConstantTimeCompare(hash, result) == 1 {
		return true, nil
	}
	return false, nil
}
func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
