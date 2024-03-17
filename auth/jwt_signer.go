package auth

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

type WebPushJwtSigner interface {
	VapidHeader(endpoint *url.URL, vapidPrivate, vapidPublic, subject string) (string, error)
}

type SimpleJwtSigner struct{}

func (*SimpleJwtSigner) VapidHeader(endpoint *url.URL, vapidPrivate, vapidPublic, subject string) (string, error) {
	aud := endpoint.Scheme + "://" + endpoint.Host
	exp := time.Now().Add(time.Hour * 12)

	token, err := sign(vapidPrivate, vapidPublic, subject, aud, exp)
	if err != nil {
		return "", err
	}

	return authHeader(token, vapidPublic), nil
}

type headerRecord struct {
	header string
	exp    time.Time
}

type CachedJwtSigner struct {
	headers *sync.Map
}

func NewCachedJwtSigner() *CachedJwtSigner {
	return &CachedJwtSigner{
		headers: &sync.Map{},
	}
}

func (c *CachedJwtSigner) VapidHeader(endpoint *url.URL, vapidPrivate, vapidPublic, subject string) (string, error) {
	aud := endpoint.Scheme + "://" + endpoint.Host

	key := vapidPrivate + vapidPublic + aud + subject

	record, ok := c.headers.Load(key)
	if ok {
		hRecord := record.(*headerRecord)

		invDate := time.Now().Add(time.Hour*12 + time.Minute*10)
		if hRecord.exp.After(invDate) {
			return hRecord.header, nil
		}
	}

	exp := time.Now().Add(time.Hour*12 + time.Minute*30)

	token, err := sign(vapidPrivate, vapidPublic, subject, aud, exp)
	if err != nil {
		return "", err
	}

	header := authHeader(token, vapidPublic)

	c.headers.Store(key, &headerRecord{
		header: header,
		exp:    exp,
	})

	return header, nil
}

func sign(vapidPrivate, vapidPublic, subject string, aud string, exp time.Time) (string, error) {
	vapidSignature, err := DecodeVapidKeys(vapidPrivate, vapidPublic)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(subject, "mailto:") {
		subject = "mailto:" + subject
	}

	token, err := JwtToken(vapidSignature, aud, exp, subject)
	if err != nil {
		return "", err
	}

	return token, err
}

func authHeader(token string, vapidPublic string) string {
	return "vapid t=" + token + ", k=" + vapidPublic
}
