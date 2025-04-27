package model

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ooni/minivpn/internal/bytesx"
)

const TLS_AUTH_KEY_LENGTH = 20

// Key used for generating/verifying HMAC
type TLSAuthKey [TLS_AUTH_KEY_LENGTH]byte

const (
	OVPN_STATIC_KEY_BEGIN = "-----BEGINOpenVPNStatickeyV1-----"
	OVPN_STATIC_KEY_END   = "-----ENDOpenVPNStatickeyV1-----"
)

var errParsingTLSAuth = errors.New("error parsing provided tls-auth key")

func extractKeyData(encoded string) ([]byte, error) {
	s := strings.ReplaceAll(encoded, "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.TrimPrefix(s, OVPN_STATIC_KEY_BEGIN)
	s = strings.TrimSuffix(s, OVPN_STATIC_KEY_END)

	return hex.DecodeString(s)
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts the
func ExtractTLSAuthKeys(encoded string, direction int) (local TLSAuthKey, remote TLSAuthKey, err error) {
	buf, err := extractKeyData(encoded)

	// keyData can be divided into 4 equal sized "chunks" e.g. [..., a, ..., b]
	// we only need the first 20 bytes of the chunk to form the key
	n := len(buf) / 4
	a := buf[n : n+TLS_AUTH_KEY_LENGTH]
	b := buf[3*n : 3*n+TLS_AUTH_KEY_LENGTH]
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

func WriteSignature(key TLSAuthKey, buf *bytes.Buffer) {
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

func GeneratePacketHMAC(key TLSAuthKey, pack *Packet) HMACHeader {
	h := hmac.New(crypto.SHA1.New, key[:])

	// a = (replay_packet_id | timestamp)
	a := make([]byte, 8)
	binary.BigEndian.PutUint32(a[:4], uint32(pack.ReplayPacketID))
	binary.BigEndian.PutUint32(a[4:], uint32(pack.PacketTimestamp))

	h.Write(a[:])

	// b = first 9 bytes (opcode | key_id | session_id)
	b := make([]byte, 9)
	b[0] = byte(pack.Opcode << 3)
	copy(b[1:], pack.LocalSessionID[:])
	h.Write(b)

	// The remainder of the packet
	// TODO: this section heavily replicates model.packet.Bytes, would be nice to refactor
	// so we're not doubling up
	c := &bytes.Buffer{}
	// we write a byte with the number of acks, and then serialize each ack.
	nAcks := len(pack.ACKs)
	c.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bytesx.WriteUint32(c, uint32(pack.ACKs[i]))
	}
	// remote session id
	if len(pack.ACKs) > 0 {
		c.Write(pack.RemoteSessionID[:])
	}
	if pack.Opcode != P_ACK_V1 {
		bytesx.WriteUint32(c, uint32(pack.ID))
	}
	h.Write(c.Bytes())

	sig := h.Sum(nil)
	return HMACHeader(sig)
}
