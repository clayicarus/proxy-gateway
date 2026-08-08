// Package subtoken contains subscription bearer-token helpers.
package subtoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	// Length is the public URL token length. Sixteen Base62 characters provide
	// roughly 95 bits of entropy.
	Length = 16
	chars  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Legacy returns the pre-database token used by existing deployments.
func Legacy(username, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username))
	hash := mac.Sum(nil)
	return encodeBase62(hash[:12])
}

// Random returns a cryptographically random short bearer token.
func Random() (string, error) {
	result := make([]byte, Length)
	for i := range result {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", fmt.Errorf("read random token: %w", err)
			}
			// Rejection sampling avoids modulo bias.
			if b[0] < 248 { // 248 is divisible by 62
				result[i] = chars[int(b[0])%len(chars)]
				break
			}
		}
	}
	return string(result), nil
}

func encodeBase62(input []byte) string {
	result := make([]byte, Length)
	num := append([]byte(nil), input...)
	for i := Length - 1; i >= 0; i-- {
		var remainder int
		for j := range num {
			value := remainder*256 + int(num[j])
			num[j] = byte(value / len(chars))
			remainder = value % len(chars)
		}
		result[i] = chars[remainder]
	}
	return string(result)
}
