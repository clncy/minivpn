package model

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	_ "crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ooni/minivpn/internal/bytesx"
)

// The auth keys provided by the server are 64 bytes, but tls-auth
// only uses the first 20
const AUTH_KEY_TOTAL_LENGTH = 64
const TLS_AUTH_KEY_LENGTH = 20
const TLS_CRYPT_KEY_LENGTH = 32

// Key used for generating/verifying HMAC
type AuthKey [64]byte

const (
	OVPN_STATIC_KEY_BEGIN       = "-----BEGINOpenVPNStatickeyV1-----"
	OVPN_STATIC_KEY_END         = "-----ENDOpenVPNStatickeyV1-----"
	OVPN_TLS_CRYPT_V2_KEY_BEGIN = "-----BEGINOpenVPNtls-crypt-v2clientkey-----"
	OVPN_TLS_CRYPT_V2_KEY_END   = "-----ENDOpenVPNtls-crypt-v2clientkey-----"
)

var errParsingTLSAuth = errors.New("error parsing provided tls-auth key")

func extractKeyData(encoded string) ([]byte, error) {
	s := strings.ReplaceAll(encoded, "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.TrimPrefix(s, OVPN_STATIC_KEY_BEGIN)
	s = strings.TrimSuffix(s, OVPN_STATIC_KEY_END)

	return hex.DecodeString(s)
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts into a PacketAuth struct
func NewTLSCryptPacketAuth(encoded string) (*PacketAuth, error) {
	buf, err := extractKeyData(encoded)
	if err != nil {
		return nil, err
	}

	n := len(buf) / 4
	var localCipherKey, localDigestKey, remoteCipherKey, remoteDigestKey AuthKey
	copy(remoteCipherKey[:], buf[:n])
	copy(remoteDigestKey[:], buf[n:2*n])
	copy(localCipherKey[:], buf[2*n:3*n])
	copy(localDigestKey[:], buf[3*n:])
	return &PacketAuth{Mode: ControlAuthModeTLSCrypt, RemoteCipherKey: &remoteCipherKey, RemoteDigestKey: &remoteDigestKey, LocalCipherKey: &localCipherKey, LocalDigestKey: &localDigestKey}, nil
}

func NewTLSCryptV2PacketAuth(encoded string) (*PacketAuth, error) {
	b, err := extractCryptV2KeyData(encoded)
	if err != nil {
		return nil, err
	}

	// The tls-crypt-v2 block first contains 4 * AUTH_KEY_TOTAL_LENGTH keys, then a variable length WrappedClientKey
	keyData := b[:4*AUTH_KEY_TOTAL_LENGTH]
	WKc := b[4*AUTH_KEY_TOTAL_LENGTH:]

	n := len(keyData) / 4
	var localCipherKey, localDigestKey, remoteCipherKey, remoteDigestKey AuthKey
	copy(remoteCipherKey[:], keyData[:n])
	copy(remoteDigestKey[:], keyData[n:2*n])
	copy(localCipherKey[:], keyData[2*n:3*n])
	copy(localDigestKey[:], keyData[3*n:])

	return &PacketAuth{
		Mode:             ControlAuthModeTLSCryptV2,
		RemoteCipherKey:  &remoteCipherKey,
		RemoteDigestKey:  &remoteDigestKey,
		LocalCipherKey:   &localCipherKey,
		LocalDigestKey:   &localDigestKey,
		WrappedClientKey: WKc,
	}, nil
}

func extractCryptV2KeyData(encoded string) ([]byte, error) {
	s := strings.ReplaceAll(encoded, "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.TrimPrefix(s, OVPN_TLS_CRYPT_V2_KEY_BEGIN)
	s = strings.TrimSuffix(s, OVPN_TLS_CRYPT_V2_KEY_END)

	return base64.StdEncoding.DecodeString(s)
}

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts the
func ExtractTLSAuthKeys(encoded string, direction int) (local AuthKey, remote AuthKey, err error) {
	buf, err := extractKeyData(encoded)

	// keyData can be divided into 4 equal sized "chunks" e.g. [..., a, ..., b]
	// we only need the first 20 bytes of the chunk to form the key
	n := len(buf) / 4
	a := buf[n : n+AUTH_KEY_TOTAL_LENGTH]
	b := buf[3*n : 3*n+AUTH_KEY_TOTAL_LENGTH]
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

// Accepts a OpenVPN Static key V1 PEM formatted block and extracts the
func ExtractTLSCryptKeys(encoded string, direction int) (local AuthKey, remote AuthKey, err error) {
	buf, err := extractKeyData(encoded)

	// keyData can be divided into 4 equal sized "chunks" e.g. [..., a, ..., b]
	// we only need the first 20 bytes of the chunk to form the key
	n := len(buf) / 4
	a := buf[n : n+AUTH_KEY_TOTAL_LENGTH]
	b := buf[3*n : 3*n+AUTH_KEY_TOTAL_LENGTH]
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

func GeneratePacketHMAC(key AuthKey, pack *Packet) SHA1HMACHeader {
	h := hmac.New(crypto.SHA1.New, key[:TLS_AUTH_KEY_LENGTH])

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
		c.Write(pack.Payload)
	}
	h.Write(c.Bytes())

	sig := h.Sum(nil)
	return SHA1HMACHeader(sig)
}

// refactor!
func GeneratePacketHMACTLSCrypt(key AuthKey, pack *Packet) SHA256HMACHeader {
	h := hmac.New(crypto.SHA256.New, key[:TLS_CRYPT_KEY_LENGTH])

	// header = first 17 bytes (opcode | key_id | session_id | replay_packet_id | timestamp)
	header := make([]byte, 17)
	header[0] = byte(pack.Opcode << 3)
	copy(header[1:9], pack.LocalSessionID[:])
	binary.BigEndian.PutUint32(header[9:13], uint32(pack.ReplayPacketID))
	binary.BigEndian.PutUint32(header[13:17], uint32(pack.PacketTimestamp))

	h.Write(header)

	ctrl := &bytes.Buffer{}
	// we write a byte with the number of acks, and then serialize each ack.
	nAcks := len(pack.ACKs)
	ctrl.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bytesx.WriteUint32(ctrl, uint32(pack.ACKs[i]))
	}
	// remote session id
	if len(pack.ACKs) > 0 {
		ctrl.Write(pack.RemoteSessionID[:])
	}
	if pack.Opcode != P_ACK_V1 {
		// Message-level packet id
		bytesx.WriteUint32(ctrl, uint32(pack.ID))
		ctrl.Write(pack.Payload)
	}
	h.Write(ctrl.Bytes())

	sig := h.Sum(nil)
	return SHA256HMACHeader(sig)
}

func EncryptControlMessage(hmac SHA256HMACHeader, key AuthKey, msg []byte) ([]byte, error) {
	return doControlAESXOR(hmac, key, msg)
}

func DecryptControlMessage(hmac SHA256HMACHeader, key AuthKey, ct []byte) ([]byte, error) {
	return doControlAESXOR(hmac, key, ct)
}

// Since performing an XOR with the key stream is a symmetric function, the
// exact same operation can be performed for both encryption and decryption
func doControlAESXOR(hmac SHA256HMACHeader, key AuthKey, in []byte) ([]byte, error) {
	out := make([]byte, len(in))

	// OpenVPN uses first 16 bytes of HMAC as IV
	iv := hmac[:16]

	// 3. AES-256-CTR encryption
	block, err := aes.NewCipher(key[:32]) // only use first 32 bytes
	if err != nil {
		return out, err
	}
	ctr := cipher.NewCTR(block, iv)

	ctr.XORKeyStream(out, in)

	return out, nil
}
