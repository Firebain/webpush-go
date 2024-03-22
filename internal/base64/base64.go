package base64

import "encoding/base64"

func DecodeUrlBase64(key string) ([]byte, error) {
	if len(key)%4 == 0 && key[len(key)-1] == '=' {
		return base64.URLEncoding.DecodeString(key)
	} else {
		return base64.RawURLEncoding.DecodeString(key)
	}
}
