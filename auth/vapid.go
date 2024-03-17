package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
)

func DecodeVapidKeys(privateKey string, publicKey string) (*ecdsa.PrivateKey, error) {
	pKeyBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	curve := elliptic.P256()

	pKey := ecdsa.PublicKey{}
	pKey.Curve = curve
	pKey.X, pKey.Y = elliptic.Unmarshal(curve, pKeyBytes)

	keyBytes, err := base64.RawURLEncoding.DecodeString(privateKey)
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
	keyBytes, err := base64.RawURLEncoding.DecodeString(privateKey)
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
