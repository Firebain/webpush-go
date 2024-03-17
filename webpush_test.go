package webpush

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/Firebain/webpush-go/auth"
	"github.com/Firebain/webpush-go/ece"
)

type clientMock struct {
	Called bool
}

func (c *clientMock) Do(req *http.Request) (*http.Response, error) {
	c.Called = true

	return &http.Response{
		StatusCode: 201,
		Status:     "201 Created",
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}, nil
}

func TestSendNotification(t *testing.T) {
	info := WebPushInfo{
		Subscription: Subscription{
			Endpoint: "https://test-ns.com/ns/token",
			Keys: SubscriptionKeys{
				P256DH: "BFGGjgyqdoqg10kasOdjQ9M_XCGCUrHe9XdOtFtGgRQmxseX0rDCPnmkqUXK0sEhF30to0G4TonsvnxWq6BJrIA",
				Auth:   "PVi3VfghXXXOELqDxy0oDA",
			},
		},
		VapidDetails: VapidDetails{
			Subject: "example@push.com",
			VapidKeys: VapidKeys{
				PrivateKey: "BdqJiVn-wHy0Jsr8kJ9kAceyuihPf31RiBP7SWtG5eU",
				PublicKey:  "BC6EjsLzlGi7OaUSrB0MuURkbcdgq8XsTR3EwqwDhclzmh9xPCtpp50UCYgUV3IKwy3onLBhrtlWJktGzFapjGc",
			},
		},
	}

	client := clientMock{}
	jwtSigner := auth.SimpleJwtSigner{}
	encoder := ece.Aes128GcmEncoder{}

	webpush := NewWebPushClient(&client, &jwtSigner, &encoder)

	res, err := webpush.Send([]byte("Hello World!"), &info, nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}
