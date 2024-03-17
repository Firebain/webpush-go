package ece

import (
	"crypto/sha256"
)

const blockSize = 64

func hkdfExtract(salt []byte, secret []byte) []byte {
	hash := sha256.New()

	ipadKey := make([]byte, blockSize)
	opadKey := make([]byte, blockSize)
	copy(ipadKey, salt)
	copy(opadKey, salt)
	for i := range blockSize {
		ipadKey[i] ^= 0x36
		opadKey[i] ^= 0x5c
	}

	hash.Write(ipadKey)
	hash.Write(secret)
	keyIn := hash.Sum(nil)

	hash.Reset()

	hash.Write(opadKey)
	hash.Write(keyIn)

	return hash.Sum(nil)
}

func hkdfExpand(prk []byte, info []byte, length int) []byte {
	hash := sha256.New()

	ipadKey := make([]byte, blockSize)
	opadKey := make([]byte, blockSize)
	copy(ipadKey, prk)
	copy(opadKey, prk)
	for i := range blockSize {
		ipadKey[i] ^= 0x36
		opadKey[i] ^= 0x5c
	}

	hash.Write(ipadKey)
	hash.Write(info)
	hash.Write([]byte{1})

	prkIn := hash.Sum(nil)

	hash.Reset()

	hash.Write(opadKey)
	hash.Write(prkIn)

	out := hash.Sum(nil)

	return out[:length]
}
