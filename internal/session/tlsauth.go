package session

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ooni/minivpn/internal/model"
)

const (
	OVPN_STATIC_KEY_BEGIN = "-----BEGIN OpenVPN Static key V1-----"
	OVPN_STATIC_KEY_END   = "-----END OpenVPN Static key V1-----"
)

var errParsingTLSAuth = errors.New("error parsing provided tls-auth key")

func extractKeyData(encoded string) ([]byte, error) {
	s := strings.TrimPrefix(encoded, OVPN_STATIC_KEY_BEGIN)
	s = strings.TrimSuffix(s, OVPN_STATIC_KEY_END)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	return hex.DecodeString(s)
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts the
func ExtractTLSAuthKeys(encoded string, direction int) (local model.TLSAuthKey, remote model.TLSAuthKey, err error) {
	if !strings.HasPrefix(encoded, OVPN_STATIC_KEY_BEGIN) || !strings.HasSuffix(encoded, OVPN_STATIC_KEY_END) {
		err = errParsingTLSAuth
		return
	}

	buf, err := extractKeyData(encoded)

	// keyData can be divided into 4 equal sized "chunks" e.g. [..., a, ..., b]
	// we only need the first 20 bytes of the chunk to form the key
	n := len(buf) / 4
	a := buf[n : n+model.TLS_AUTH_KEY_LENGTH]
	b := buf[3*n : 3*n+model.TLS_AUTH_KEY_LENGTH]
	switch direction {
	case 0:
		copy(local[:], a)
		copy(remote[:], b)
	case 1:
		copy(local[:], b)
		copy(remote[:], a)
	}

	return
}

func WriteSignature(key model.TLSAuthKey, buf *bytes.Buffer) {
	p := buf.Bytes()
	l1 := 9
	l2 := 20
	l3 := 8

	h := hmac.New(crypto.SHA1.New, key[:])
	a := p[l1+l2 : l1+l2+l3]
	h.Write(a)

	b := p[0:l1]
	h.Write(b)

	c := p[l1+l2+l3:]
	h.Write(c)

	sig := h.Sum(nil)

	j := l1
	for i := 0; i < len(sig); i++ {
		p[j] = sig[i]
		j++
	}
}
