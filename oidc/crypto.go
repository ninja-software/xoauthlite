package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// Adapted from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb

func init() {
	assertAvailablePRNG()
}

func assertAvailablePRNG() {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// GenerateRandomBytes generate random bytes of a specified length
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomStringURLSafe generate random string of a specified length in url safe string
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateBase64Sha256Hash generate hex string of sha256 from string input
func GenerateBase64Sha256Hash(input string) string {
	hashFunc := sha256.New()
	hashFunc.Write([]byte(input))

	var hashBytes = hashFunc.Sum([]byte{})
	var hashStr = base64.RawURLEncoding.EncodeToString(hashBytes)

	return hashStr
}
