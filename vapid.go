package webpush

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

func GenerateVapidKeys() (*VapidKeys, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	private := base64.RawURLEncoding.EncodeToString(key.Bytes())
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())

	return &VapidKeys{
		PrivateKey: private,
		PublicKey:  public,
	}, nil
}
