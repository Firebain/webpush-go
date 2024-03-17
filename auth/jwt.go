package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

var jwtHeader string

func init() {
	header := []byte(`{"alg":"ES256","typ":"JWT"}`)

	jwtHeader = base64.RawURLEncoding.EncodeToString(header)
}

func JwtToken(signKey *ecdsa.PrivateKey, aud string, exp time.Time, subject string) (string, error) {
	data := fmt.Sprintf(`{"aud":"%s","exp":%d,"sub":"%s"}`, aud, exp.Unix(), subject)

	body := base64.RawURLEncoding.EncodeToString([]byte(data))

	payload := jwtHeader + "." + body

	hash := sha256.Sum256([]byte(payload))

	r, s, err := ecdsa.Sign(rand.Reader, signKey, hash[:])
	if err != nil {
		return "", err
	}

	out := make([]byte, 2*32)
	r.FillBytes(out[0:32])
	s.FillBytes(out[32:])

	sig := base64.RawURLEncoding.EncodeToString(out)

	return payload + "." + sig, nil
}
