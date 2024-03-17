package webpush

type SubscriptionKeys struct {
	P256DH string `json:"p256dh"`
	Auth   string `json:"auth"`
}

type Subscription struct {
	Endpoint string           `json:"endpoint"`
	Keys     SubscriptionKeys `json:"keys"`
}

type VapidKeys struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type VapidDetails struct {
	Subject   string `json:"subject"`
	VapidKeys `json:",inline"`
}

type WebPushInfo struct {
	Subscription Subscription
	VapidDetails VapidDetails
}
