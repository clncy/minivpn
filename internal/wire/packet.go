package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
)

// ErrEmptyPayload indicates tha the payload of an OpenVPN control packet is empty.
var ErrEmptyPayload = errors.New("openvpn: empty payload")

// ErrParsePacket is a generic packet parse error which may be further qualified.
var ErrParsePacket = errors.New("openvpn: packet parse error")

// ErrMarshalPacket is the error returned when we cannot marshal a packet.
var ErrMarshalPacket = errors.New("cannot marshal packet")

// ErrPacketTooShort indicates that a packet is too short.
var ErrPacketTooShort = errors.New("openvpn: packet too short")

func MarshalPacket(p *model.Packet, packetAuth *ControlChannelSecurity) ([]byte, error) {
	buf := &bytes.Buffer{}

	switch p.Opcode {
	case model.P_DATA_V2:
		// we assume this is an encrypted data packet,
		// so we serialize just the encrypted payload

	default:
		buf.WriteByte((byte(p.Opcode) << 3) | (p.KeyID & 0x07))
		buf.Write(p.LocalSessionID[:])

		switch packetAuth.Mode {
		case ControlSecurityModeNone:
			err := writeACKDataToBuffer(buf, p)
			if err != nil {
				return nil, err
			}
			if p.Opcode != model.P_ACK_V1 {
				bytesx.WriteUint32(buf, uint32(p.ID))
			}
			//  payload
			buf.Write(p.Payload)

		case ControlSecurityModeTLSAuth:
			hmacDigest := GeneratePacketHMAC(*packetAuth.LocalDigestKey, p)
			buf.Write(hmacDigest[:])
			bytesx.WriteUint32(buf, uint32(p.ReplayPacketID))
			bytesx.WriteUint32(buf, uint32(p.PacketTimestamp))

			err := writeACKDataToBuffer(buf, p)
			if err != nil {
				return nil, err
			}
			if p.Opcode != model.P_ACK_V1 {
				bytesx.WriteUint32(buf, uint32(p.ID))
			}
			//  payload
			buf.Write(p.Payload)

		// Note HMAC header is in a different position than tls-auth
		case ControlSecurityModeTLSCrypt, ControlSecurityModeTLSCryptV2:
			bytesx.WriteUint32(buf, uint32(p.ReplayPacketID))
			bytesx.WriteUint32(buf, uint32(p.PacketTimestamp))

			hmacDigest := GeneratePacketHMACTLSCrypt(*packetAuth.LocalDigestKey, p)
			buf.Write(hmacDigest[:])

			ctrl := &bytes.Buffer{}
			// we write a byte with the number of acks, and then serialize each ack.
			nAcks := len(p.ACKs)
			ctrl.WriteByte(byte(nAcks))
			for i := 0; i < nAcks; i++ {
				bytesx.WriteUint32(ctrl, uint32(p.ACKs[i]))
			}
			// remote session id
			if len(p.ACKs) > 0 {
				ctrl.Write(p.RemoteSessionID[:])
			}
			if p.Opcode != model.P_ACK_V1 {
				// Message-level pet id
				bytesx.WriteUint32(ctrl, uint32(p.ID))
				ctrl.Write(p.Payload)
			}

			enc, err := EncryptControlMessage(hmacDigest, *packetAuth.LocalCipherKey, ctrl.Bytes())
			if err != nil {
				return nil, err
			}
			buf.Write(enc)

		}

		// tls-cryptv2 requires an additional "wrapped client key" to be appended to reset packets
		// which includes the client key (Kc) encrypted with a server key (not exposed to client) so
		// that the server can statelessly validate the keys used by the client
		if packetAuth.Mode == ControlSecurityModeTLSCryptV2 && p.Opcode == model.P_CONTROL_HARD_RESET_CLIENT_V3 {
			buf.Write(packetAuth.WrappedClientKey) // WKc

			// n := len(packetAuth.WrappedClientKey)
			// bytesx.WriteUint16(buf, uint32(n)) // len(WKc)
		}
	}

	return buf.Bytes(), nil
}

func writeACKDataToBuffer(buf *bytes.Buffer, p *model.Packet) error {
	// we write a byte with the number of acks, and then serialize each ack.
	nAcks := len(p.ACKs)
	if nAcks > math.MaxUint8 {
		return fmt.Errorf("%w: too many ACKs", ErrMarshalPacket)
	}
	buf.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bytesx.WriteUint32(buf, uint32(p.ACKs[i]))
	}
	// remote session id
	if len(p.ACKs) > 0 {
		buf.Write(p.RemoteSessionID[:])
	}
	return nil
}

// parseControlOrACKPacket parses the contents of a control or ACK packet.
func parseControlOrACKPacket(opcode model.Opcode, keyID byte, payload []byte, packetAuth *ControlChannelSecurity) (*model.Packet, error) {
	// make sure we have payload to parse and we're parsing control or ACK
	if len(payload) <= 0 {
		return nil, ErrEmptyPayload
	}
	if !opcode.IsControl() && opcode != model.P_ACK_V1 {
		return nil, fmt.Errorf("%w: %s", ErrParsePacket, "expected control/ack packet")
	}

	// create a buffer for parsing the packet
	buf := bytes.NewBuffer(payload)

	p := model.NewPacket(opcode, keyID, payload)

	// local session id
	if _, err := io.ReadFull(buf, p.LocalSessionID[:]); err != nil {
		return p, fmt.Errorf("%w: bad sessionID: %s", ErrParsePacket, err)
	}

	switch packetAuth.Mode {
	case ControlSecurityModeNone:
		// ack array length
		ackArrayLenByte, err := buf.ReadByte()
		if err != nil {
			return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
		}
		ackArrayLen := int(ackArrayLenByte)

		// ack array
		p.ACKs = make([]model.PacketID, ackArrayLen)
		for i := 0; i < ackArrayLen; i++ {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
			}
			p.ACKs[i] = model.PacketID(val)
		}

		// remote session id
		if ackArrayLen > 0 {
			if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
				return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
			}
		}

		// packet id
		if p.Opcode != model.P_ACK_V1 {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
			}
			p.ID = model.PacketID(val)
		}

		// payload
		p.Payload = buf.Bytes()
	case ControlSecurityModeTLSAuth:
		var hmacGot SHA1HMACDigest
		if _, err := io.ReadFull(buf, hmacGot[:]); err != nil {
			return p, fmt.Errorf("%w: bad HMAC (tls-auth): %s", ErrParsePacket, err)
		}

		// replay packet id
		replayId, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad replay packet id (tls-auth): %s", ErrParsePacket, err)
		}
		p.ReplayPacketID = model.PacketID(replayId)

		// timestamp
		timestamp, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad packet timestamp (tls-auth): %s", ErrParsePacket, err)
		}
		p.PacketTimestamp = model.PacketTimestamp(timestamp)
		// ack array length
		ackArrayLenByte, err := buf.ReadByte()
		if err != nil {
			return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
		}
		ackArrayLen := int(ackArrayLenByte)

		// ack array
		p.ACKs = make([]model.PacketID, ackArrayLen)
		for i := 0; i < ackArrayLen; i++ {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
			}
			p.ACKs[i] = model.PacketID(val)
		}

		// remote session id
		if ackArrayLen > 0 {
			if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
				return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
			}
		}

		// packet id
		if p.Opcode != model.P_ACK_V1 {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
			}
			p.ID = model.PacketID(val)
		}

		// payload
		p.Payload = buf.Bytes()

		// Now calculate the hmac digest over the parsed packet, and confirm it
		// matches what we recieved from the server. Invalid digest could indicate
		// that the server is not in possession of pre-shared key OR packet contents
		// has been tampered with
		hmacWant := GeneratePacketHMAC(*packetAuth.RemoteDigestKey, p)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		if hmacGot != hmacWant {
			return p, fmt.Errorf("%w: packet digest (hmac) is not valid", ErrParsePacket)
		}

	case ControlSecurityModeTLSCrypt, ControlSecurityModeTLSCryptV2:
		// replay packet id
		replayId, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad replay packet id (tls-auth): %s", ErrParsePacket, err)
		}
		p.ReplayPacketID = model.PacketID(replayId)

		// timestamp
		timestamp, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad packet timestamp (tls-auth): %s", ErrParsePacket, err)
		}
		p.PacketTimestamp = model.PacketTimestamp(timestamp)

		// The HMAC digest that was included with the received packet
		var hmacGot SHA256HMACDigest
		if _, err := io.ReadFull(buf, hmacGot[:]); err != nil {
			return p, fmt.Errorf("%w: bad packet digest (tls-crypt): %s", ErrParsePacket, err)
		}

		ct, err := io.ReadAll(buf)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		body, err := DecryptControlMessage(hmacGot, *packetAuth.RemoteCipherKey, ct)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		buf := bytes.NewBuffer(body)
		// ack array length
		ackArrayLenByte, err := buf.ReadByte()
		if err != nil {
			return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
		}
		ackArrayLen := int(ackArrayLenByte)

		// ack array
		p.ACKs = make([]model.PacketID, ackArrayLen)
		for i := 0; i < ackArrayLen; i++ {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
			}
			p.ACKs[i] = model.PacketID(val)
		}

		// remote session id
		if ackArrayLen > 0 {
			if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
				return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
			}
		}

		// packet id
		if p.Opcode != model.P_ACK_V1 {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
			}
			p.ID = model.PacketID(val)
		}

		// payload
		p.Payload = buf.Bytes()

		// Now calculate the hmac digest over the parsed packet, and confirm it
		// matches what we recieved from the server. Invalid digest could indicate
		// that the server is not in possession of pre-shared key OR packet contents
		// has been tampered with
		hmacWant := GeneratePacketHMACTLSCrypt(*packetAuth.RemoteDigestKey, p)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		if hmacGot != hmacWant {
			return p, fmt.Errorf("%w: packet digest (hmac) is not valid", ErrParsePacket)
		}

	}

	return p, nil
}

// UnmarshalPacket produces a packet after parsing the common header. We assume that
// the underlying connection has already stripped out the framing.
func UnmarshalPacket(buf []byte, packetAuth *ControlChannelSecurity) (*model.Packet, error) {
	// a valid packet is larger, but this allows us
	// to keep parsing a non-data packet.
	if len(buf) < 2 {
		return nil, ErrPacketTooShort
	}
	// parsing opcode and keyID
	opcode := model.Opcode(buf[0] >> 3)
	keyID := buf[0] & 0x07

	// extract the packet payload and possibly the peerID
	var (
		payload []byte
		peerID  model.PeerID
	)
	switch opcode {
	case model.P_DATA_V2:
		if len(buf) < 4 {
			return nil, ErrPacketTooShort
		}
		copy(peerID[:], buf[1:4])
		payload = buf[4:]
	default:
		payload = buf[1:]
	}

	// ACKs and control packets require more complex parsing
	if opcode.IsControl() || opcode == model.P_ACK_V1 {
		return parseControlOrACKPacket(opcode, keyID, payload, packetAuth)
	}

	// otherwise just return the data packet.
	p := &model.Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          peerID,
		LocalSessionID:  [8]byte{},
		ACKs:            []model.PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
	return p, nil
}
