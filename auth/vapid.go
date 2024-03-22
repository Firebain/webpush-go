package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/Firebain/webpush-go/internal/base64"
)

func DecodeVapidKeys(privateKey string, publicKey string) (*ecdsa.PrivateKey, error) {
	pKeyBytes, err := base64.DecodeUrlBase64(publicKey)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()

	pKey := ecdsa.PublicKey{}
	pKey.Curve = curve
	pKey.X, pKey.Y = elliptic.Unmarshal(curve, pKeyBytes)

	keyBytes, err := base64.DecodeUrlBase64(privateKey)
	if err != nil {
		return nil, err
	}

	d := new(big.Int).SetBytes(keyBytes)

	return &ecdsa.PrivateKey{
		D:         d,
		PublicKey: pKey,
	}, nil
}

func DecodeVapidPrivateKey(privateKey string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := base64.DecodeUrlBase64(privateKey)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()

	pKey := ecdsa.PublicKey{}
	pKey.Curve = curve
	pKey.X, pKey.Y = curve.ScalarBaseMult(keyBytes)

	d := new(big.Int).SetBytes(keyBytes)

	return &ecdsa.PrivateKey{
		D:         d,
		PublicKey: pKey,
	}, nil
}
