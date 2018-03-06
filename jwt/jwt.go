package jwt

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Header struct {
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func MarshalJWT(v interface{}, key []byte) (string, error) {
	header, err := json.Marshal(&Header{Typ: "JWT", Alg: "SH512"})
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	jwt := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(data)
	if err != nil {
		return "", err
	}
	hash := hmac.New(sha512.New, key)
	hash.Write([]byte(jwt))
	sig := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	return jwt + "." + sig, nil
}

func UnmarshalJWT(jwt string, v interface{}, key []byte) error {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return errors.New("jwt invalid")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	header := &Header{}
	if err := json.Unmarshal([]byte(headerJSON), header); err != nil {
		return err
	}
	if header.Alg != "SH512" {
		return errors.New("unsupported alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	hash := hmac.New(sha512.New, key)
	hash.Write([]byte(parts[0]))
	hash.Write([]byte("."))
	hash.Write([]byte(parts[1]))
	if !hmac.Equal(hash.Sum(nil), sig) {
		return errors.New("signature invalid")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}
