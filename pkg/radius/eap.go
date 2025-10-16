package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"

	radiuslib "layeh.com/radius"
)

const (
	radiusTypeEAPMessage           = radiuslib.Type(79)
	radiusTypeMessageAuthenticator = radiuslib.Type(80)
)

const (
	eapCodeRequest  = 1
	eapCodeResponse = 2
	eapCodeSuccess  = 3
	eapCodeFailure  = 4
)

const (
	eapTypeIdentity = 1
	eapTypeTLS      = 13
)

const (
	eapTLSFlagLengthIncluded = 1 << 7
	eapTLSFlagMoreFragments  = 1 << 6
	eapTLSFlagStart          = 1 << 5
)

// eapMessage represents an EAP packet as defined in RFC 3748/RFC 5216.
type eapMessage struct {
	Code             uint8
	Identifier       uint8
	Type             uint8
	Flags            uint8
	TLSMessageLength int
	Data             []byte
}

func (m *eapMessage) marshal() ([]byte, error) {
	if m == nil {
		return nil, errors.New("radius: nil eapMessage")
	}
	payload := make([]byte, 0, 5+len(m.Data))

	switch m.Code {
	case eapCodeRequest, eapCodeResponse:
		payload = append(payload, m.Type)
		if m.Type == eapTypeTLS {
			payload = append(payload, m.Flags)
			if m.Flags&eapTLSFlagLengthIncluded != 0 {
				length := m.TLSMessageLength
				if length == 0 {
					length = len(m.Data)
				}
				buf := make([]byte, 4)
				binary.BigEndian.PutUint32(buf, uint32(length))
				payload = append(payload, buf...)
			}
		}
		payload = append(payload, m.Data...)
	case eapCodeSuccess, eapCodeFailure:
		// No Type/Data in success/failure
	default:
		return nil, errors.New("radius: unsupported EAP code")
	}

	totalLength := 4 + len(payload)
	if totalLength > 0xffff {
		return nil, errors.New("radius: EAP message too long")
	}

	b := make([]byte, totalLength)
	b[0] = m.Code
	b[1] = m.Identifier
	binary.BigEndian.PutUint16(b[2:], uint16(totalLength))
	copy(b[4:], payload)
	return b, nil
}

func parseEAPMessage(raw []byte) (*eapMessage, error) {
	if len(raw) < 4 {
		return nil, errors.New("radius: short EAP message")
	}
	code := raw[0]
	identifier := raw[1]
	length := binary.BigEndian.Uint16(raw[2:4])
	if int(length) > len(raw) {
		return nil, errors.New("radius: truncated EAP message")
	}
	payload := raw[4:length]

	msg := &eapMessage{Code: code, Identifier: identifier}
	switch code {
	case eapCodeRequest, eapCodeResponse:
		if len(payload) == 0 {
			return nil, errors.New("radius: missing EAP type")
		}
		msg.Type = payload[0]
		payload = payload[1:]
		if msg.Type == eapTypeTLS {
			if len(payload) == 0 {
				return nil, errors.New("radius: missing EAP-TLS flags")
			}
			msg.Flags = payload[0]
			payload = payload[1:]
			if msg.Flags&eapTLSFlagLengthIncluded != 0 {
				if len(payload) < 4 {
					return nil, errors.New("radius: missing EAP-TLS length")
				}
				msg.TLSMessageLength = int(binary.BigEndian.Uint32(payload[:4]))
				payload = payload[4:]
			}
		}
		msg.Data = append([]byte(nil), payload...)
	case eapCodeSuccess, eapCodeFailure:
		if len(payload) != 0 {
			return nil, errors.New("radius: unexpected payload in EAP success/failure")
		}
	default:
		return nil, errors.New("radius: unsupported EAP code")
	}
	return msg, nil
}

func setEAPMessageAttr(packet *radiuslib.Packet, msg *eapMessage) error {
	raw, err := msg.marshal()
	if err != nil {
		return err
	}

	packet.Attributes.Del(radiusTypeEAPMessage)
	for len(raw) > 0 {
		chunkLen := len(raw)
		if chunkLen > 253 {
			chunkLen = 253
		}
		chunk := make([]byte, chunkLen)
		copy(chunk, raw[:chunkLen])
		packet.Attributes.Add(radiusTypeEAPMessage, chunk)
		raw = raw[chunkLen:]
	}
	return nil
}

func getEAPMessageAttr(packet *radiuslib.Packet) ([]byte, error) {
	var buf bytes.Buffer
	for _, avp := range packet.Attributes {
		if avp.Type == radiusTypeEAPMessage {
			buf.Write(avp.Attribute)
		}
	}
	if buf.Len() == 0 {
		return nil, errors.New("radius: missing EAP-Message attribute")
	}
	return buf.Bytes(), nil
}

func setMessageAuthenticator(packet *radiuslib.Packet, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("radius: secret required for Message-Authenticator")
	}
	zeros := make([]byte, md5.Size)
	packet.Attributes.Set(radiusTypeMessageAuthenticator, zeros)
	raw, err := packet.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(raw)
	sum := mac.Sum(nil)
	packet.Attributes.Set(radiusTypeMessageAuthenticator, sum)
	return nil
}

func verifyMessageAuthenticator(packet *radiuslib.Packet, secret []byte) error {
	attr, ok := packet.Attributes.Lookup(radiusTypeMessageAuthenticator)
	if !ok {
		return errors.New("radius: missing Message-Authenticator")
	}
	if len(secret) == 0 {
		return errors.New("radius: secret required for Message-Authenticator verification")
	}

	original := make([]byte, len(attr))
	copy(original, attr)

	zeros := make([]byte, len(attr))
	packet.Attributes.Set(radiusTypeMessageAuthenticator, zeros)
	raw, err := packet.MarshalBinary()
	if err != nil {
		return err
	}

	mac := hmac.New(md5.New, secret)
	mac.Write(raw)
	expected := mac.Sum(nil)
	packet.Attributes.Set(radiusTypeMessageAuthenticator, original)

	if !hmac.Equal(expected, original) {
		return errors.New("radius: invalid Message-Authenticator")
	}
	return nil
}

func messageAuthenticatorAllZeros(packet *radiuslib.Packet) bool {
	attr, ok := packet.Attributes.Lookup(radiusTypeMessageAuthenticator)
	if !ok {
		return false
	}
	for _, b := range attr {
		if b != 0 {
			return false
		}
	}
	return true
}
