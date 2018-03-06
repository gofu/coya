package jwt

import "testing"

type testJWT struct {
	JTI string `json:"jti"`
}

func TestMarshalJWT(t *testing.T) {
	key := []byte("asdf")
	jwtIn := &testJWT{JTI: "asdfgh"}
	cookie, err := MarshalJWT(jwtIn, key)
	if err != nil {
		t.Fatal(err)
	}
	jwtOut := &testJWT{}
	if err := UnmarshalJWT(cookie, jwtOut, key); err != nil {
		t.Fatal(err)
	}
	if jwtIn.JTI != jwtOut.JTI {
		t.Fatal("JWT does not match")
	}
}
