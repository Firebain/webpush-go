package ece

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/Firebain/webpush-go/internal/base64"
)

type WebPushEncoder interface {
	EncryptPayload(p256dh string, auth string, data []byte) ([]byte, error)
}

const DefaultBlockSize = 128

const defaultRs = 4096

const ikmInfoLength = 144 // 14 (prefix len) + 65 (pub key len) * 2
const headerLength = 86   // 16 (salt) + 4 (rs) + 1 (pub key len) + 65 (pub key)

const ikmLength = 32
const aesKeyLength = 16
const nonceLength = 12

const authenticationTagLength = 16
const delimiterLength = 1

func genSalt() ([]byte, error) {
	salt := make([]byte, 16)

	_, err := io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return salt, err
	}

	return salt, nil
}

func deriveKeyAndNonce(salt []byte, auth []byte, remoteKey *ecdh.PublicKey, localKey *ecdh.PrivateKey) ([]byte, []byte, error) {
	sharedSecret, err := localKey.ECDH(remoteKey)
	if err != nil {
		return nil, nil, err
	}

	ikmBuf := make([]byte, 0, ikmInfoLength)
	ikmInfo := bytes.NewBuffer(ikmBuf)
	ikmInfo.Write([]byte("WebPush: info\x00"))
	ikmInfo.Write(remoteKey.Bytes())
	ikmInfo.Write(localKey.PublicKey().Bytes())

	prk := hkdfExtract(auth, sharedSecret)
	ikm := hkdfExpand(prk, ikmInfo.Bytes(), ikmLength)

	keyInfo := []byte("Content-Encoding: aes128gcm\x00")

	prk = hkdfExtract(salt, ikm)

	key := hkdfExpand(prk, keyInfo, aesKeyLength)

	nonceInfo := []byte("Content-Encoding: nonce\x00")
	nonce := hkdfExpand(prk, nonceInfo, nonceLength)

	return key, nonce, nil
}

type Aes128GcmEncoder struct{}

func (*Aes128GcmEncoder) Encrypt(
	salt []byte,
	localKey *ecdh.PrivateKey,
	p256dh []byte,
	auth []byte,
	padSize int,
	data []byte,
) ([]byte, error) {
	remoteKey, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, err
	}

	key, nonce, err := deriveKeyAndNonce(salt, auth, remoteKey, localKey)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	dataWithDelLength := len(data) + delimiterLength

	padLength := 0
	if padSize != 0 {
		padLength = padSize - dataWithDelLength%padSize
	}

	fullDataSize := dataWithDelLength + padLength

	recordInitBuf := make([]byte, 0, headerLength+fullDataSize+authenticationTagLength)
	recordBuf := bytes.NewBuffer(recordInitBuf)
	recordBuf.Write(salt)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, defaultRs)

	localPublicKey := localKey.PublicKey().Bytes()

	recordBuf.Write(rs)
	recordBuf.WriteByte(byte(len(localPublicKey)))
	recordBuf.Write(localPublicKey)

	dataBuf := make([]byte, fullDataSize+authenticationTagLength)
	offset := copy(dataBuf, data)
	dataBuf[offset] = 0x02

	ciphertext := gcm.Seal(dataBuf[:0], nonce, dataBuf[:fullDataSize], nil)
	recordBuf.Write(ciphertext)

	return recordBuf.Bytes(), err
}

func (e *Aes128GcmEncoder) EncryptPayload(p256dhEncoded string, authEncoded string, data []byte) ([]byte, error) {
	if len(data) > defaultRs {
		return nil, errors.New("payload too large")
	}

	p256dh, err := base64.DecodeUrlBase64(p256dhEncoded)
	if err != nil {
		return nil, err
	}

	if len(p256dh) != 65 {
		return nil, errors.New("invalid key length")
	}

	auth, err := base64.DecodeUrlBase64(authEncoded)
	if err != nil {
		return nil, err
	}

	if len(auth) != 16 {
		return nil, errors.New("invalid auth secret")
	}

	salt, err := genSalt()
	if err != nil {
		return nil, err
	}

	localKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return e.Encrypt(
		salt,
		localKey,
		p256dh,
		auth,
		DefaultBlockSize,
		data,
	)
}
