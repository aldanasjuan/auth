package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// Header has timestamp and exp, both in Unix
type Header struct {
	Timestamp int64 `json:"timestamp,omitempty"`
	Exp       int64 `json:"exp,omitempty"`
}

func (h Header) JSON() []byte {
	return []byte(fmt.Sprintf(`{"timestamp": %d, "exp": %d}`, h.Timestamp, h.Exp))
}

var Expired = errors.New("expired token")
var WrongFormat = errors.New("wrong format")
var Invalid = errors.New("invalid")

/* TODO
Create a tokenA

use tokenA plus signature to sign a tokenB (child)

New()   return tokenA
NewChild() return tokenB
Validate() takes a token and returns claims

*/

func NewToken(payload []byte, timestamp, exp int64, key []byte) (token string, err error) {

	head := Header{Timestamp: timestamp, Exp: exp}.JSON()
	hasher := hmac.New(sha256.New, key)
	//
	hj := append(payload, head...)

	_, err = hasher.Write(hj)
	if err != nil {
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	claims := base64.RawURLEncoding.EncodeToString(payload)
	header := base64.RawURLEncoding.EncodeToString(head)
	token = header + "." + claims + "." + signature
	return token, nil
}

// ValidateToken validates token with a given secret key and returns header and claims
func ValidateToken(token string, key []byte) (*Header, []byte, error) {
	strs := strings.Split(token, ".")
	if len(strs) != 3 {
		return nil, nil, WrongFormat
	}
	a, _ := base64.RawURLEncoding.DecodeString(strs[0])
	b, _ := base64.RawURLEncoding.DecodeString(strs[1])
	// s,_ := base64.RawURLEncoding.DecodeString(strs[2])
	// fmt.Println(s)

	var h Header
	err := jsoniter.Unmarshal(a, &h)
	if err != nil {
		return nil, nil, err
	}
	t, err := NewToken(b, h.Timestamp, h.Exp, key)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
		if h.Exp < time.Now().Unix() {
			return nil, nil, Expired
		}
		return &h, b, nil
	}
	return nil, nil, Invalid

}

// RandomBytes generates n bytes
func RandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
