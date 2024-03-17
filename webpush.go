package webpush

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Firebain/webpush-go/auth"
	"github.com/Firebain/webpush-go/ece"
)

const DefaultTTL = 4 * 7 * 24 * 60 * 60

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type WebPushOptions struct {
	Urgency string
	Topic   string
	TTL     int
}

type WebPushClient struct {
	httpClient HTTPClient
	jwtSigner  auth.WebPushJwtSigner
	encoder    ece.WebPushEncoder
}

func DefaultWebPushClient() *WebPushClient {
	httpClient := http.Client{}
	jwtSigner := auth.SimpleJwtSigner{}
	encoder := ece.Aes128GcmEncoder{}

	return NewWebPushClient(
		&httpClient,
		&jwtSigner,
		&encoder,
	)
}

func NewWebPushClient(httpClient HTTPClient, jwtSigner auth.WebPushJwtSigner, encoder ece.WebPushEncoder) *WebPushClient {
	return &WebPushClient{
		httpClient: httpClient,
		jwtSigner:  jwtSigner,
		encoder:    encoder,
	}
}

func (c *WebPushClient) Send(payload []byte, info *WebPushInfo, options *WebPushOptions) (*http.Response, error) {
	endpoint, err := url.Parse(info.Subscription.Endpoint)
	if err != nil {
		return nil, err
	}

	vapidHeader, err := c.jwtSigner.VapidHeader(
		endpoint,
		info.VapidDetails.PrivateKey,
		info.VapidDetails.PublicKey,
		info.VapidDetails.Subject,
	)
	if err != nil {
		return nil, err
	}

	p256dh, err := base64.RawURLEncoding.DecodeString(info.Subscription.Keys.P256DH)
	if err != nil {
		return nil, err
	}

	auth, err := base64.RawURLEncoding.DecodeString(info.Subscription.Keys.Auth)
	if err != nil {
		return nil, err
	}

	encrypted, err := c.encoder.EncryptPayload(p256dh, auth, []byte(payload))
	if err != nil {
		return nil, err
	}

	body := bytes.NewReader(encrypted)

	req, err := http.NewRequest("POST", info.Subscription.Endpoint, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", vapidHeader)
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Content-Length", strconv.Itoa(len(encrypted)))
	req.Header.Add("Content-Encoding", "aes128gcm")

	if options != nil {
		if options.Urgency != "" {
			req.Header.Add("Urgency", "normal")
		}

		if options.Topic != "" {
			req.Header.Add("Topic", "topic")
		}

		req.Header.Add("TTL", strconv.Itoa(options.TTL))
	} else {
		req.Header.Add("TTL", strconv.Itoa(DefaultTTL))
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
