package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestJwtToken(t *testing.T) {
	signKey, err := DecodeVapidKeys(
		"F4uhvy_ej2DySTchnmJSpra62xFUK5KrMkWaOPB5VgU",
		"BAHN13txEjbVBbZik4WjbNB7eGgLybxTUiIpBdMfAGvdOO9lv4hxq_ZjdJZxvmUdsUQNV-V2eKkFHOQ_uhDrGXI",
	)
	if err != nil {
		t.Fatal(err)
	}

	token, err := JwtToken(
		signKey,
		"https://test-ns.com",
		time.Unix(1710588595, 0),
		"example@push.com",
	)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(token)

	if !strings.HasPrefix(token, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3Rlc3QtbnMuY29tIiwiZXhwIjoxNzEwNTg4NTk1LCJzdWIiOiJleGFtcGxlQHB1c2guY29tIn0.") {
		t.Log(token)
		t.Fatal("Jwt token doesn't match")
	}
}
