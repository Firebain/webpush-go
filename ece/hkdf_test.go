package ece

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestHkdf(t *testing.T) {
	auth, err := base64.RawURLEncoding.DecodeString("qdI_6MesWshSaootRWyzSw")
	if err != nil {
		t.Fatal(err)
	}

	sharedSecret, err := base64.RawURLEncoding.DecodeString("dZBzmzwhneD4QgVC7i7nGCTg-9e4EZvIhUo-JpVr1zg")
	if err != nil {
		t.Fatal(err)
	}

	expectedPrk, err := base64.RawURLEncoding.DecodeString("b9-MzS5bHL-gIZh2prVGDy_Augv5W874MTfBrXx2oTc")
	if err != nil {
		t.Fatal(err)
	}

	prk := hkdfExtract(auth, sharedSecret)
	if !bytes.Equal(prk, expectedPrk) {
		t.Errorf("Unexpected prk")
	}

	ikmInfo, err := base64.RawURLEncoding.DecodeString("V2ViUHVzaDogaW5mbwAELtvvhbW3w1L4X-D6W-g4QQe4j-FoxG04nlthECYPdYS2TgeOgu3tJESfYTJM0gCCB4CqwUVu5J3EGE0uREAylASYJ7P3HuczBOfO4LmjhLAopDcDDWK9IWHsTMYefs2KEfU3wjnhWUnXK-yYQ1dxezei7cGnLqlcFz9ZrOVt4W2r")
	if err != nil {
		t.Fatal(err)
	}

	expectedIkm, err := base64.RawURLEncoding.DecodeString("eCribN7Mf-pkn3Q_bzUFtHevJ4w4UzvitbzfrpssAYc")
	if err != nil {
		t.Fatal(err)
	}

	ikm := hkdfExpand(prk, ikmInfo, 32)
	if !bytes.Equal(ikm, expectedIkm) {
		t.Errorf("Unexpected ikm")
	}
}
