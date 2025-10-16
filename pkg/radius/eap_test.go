package radius

import (
	"bytes"
	"crypto/md5"
	"testing"

	radiuslib "layeh.com/radius"
)

func TestEAPIdentityMarshalRoundTrip(t *testing.T) {
	msg := &eapMessage{Code: eapCodeResponse, Identifier: 5, Type: eapTypeIdentity, Data: []byte("alice")}
	raw, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	parsed, err := parseEAPMessage(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Code != msg.Code || parsed.Identifier != msg.Identifier || parsed.Type != msg.Type || string(parsed.Data) != "alice" {
		t.Fatalf("unexpected parsed message: %+v", parsed)
	}
}

func TestEAPTLSMarshalRoundTrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	msg := &eapMessage{
		Code:             eapCodeResponse,
		Identifier:       10,
		Type:             eapTypeTLS,
		Flags:            eapTLSFlagLengthIncluded | eapTLSFlagStart,
		TLSMessageLength: len(payload),
		Data:             payload,
	}
	raw, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	parsed, err := parseEAPMessage(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Flags != msg.Flags || parsed.TLSMessageLength != len(payload) || string(parsed.Data) != string(payload) {
		t.Fatalf("unexpected parsed message: %+v", parsed)
	}
}

func TestEAPAttributeChunking(t *testing.T) {
	packet := radiuslib.New(radiuslib.CodeAccessRequest, []byte("secret"))
	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i % 251)
	}
	msg := &eapMessage{Code: eapCodeResponse, Identifier: 1, Type: eapTypeTLS, Data: data}
	if err := setEAPMessageAttr(packet, msg); err != nil {
		t.Fatalf("set attribute error: %v", err)
	}

	raw, err := getEAPMessageAttr(packet)
	if err != nil {
		t.Fatalf("get attribute error: %v", err)
	}
	expected, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("mismatched raw data")
	}
}

func TestMessageAuthenticatorSetVerify(t *testing.T) {
	secret := []byte("sharedsecret")
	packet := radiuslib.New(radiuslib.CodeAccessRequest, secret)
	if err := setMessageAuthenticator(packet, secret); err != nil {
		t.Fatalf("setMessageAuthenticator error: %v", err)
	}
	if err := verifyMessageAuthenticator(packet, secret); err != nil {
		t.Fatalf("verifyMessageAuthenticator error: %v", err)
	}
	if messageAuthenticatorAllZeros(packet) {
		t.Fatalf("expected non-zero message authenticator")
	}

	// Tamper with attribute
	attr, _ := packet.Attributes.Lookup(radiusTypeMessageAuthenticator)
	attr[0] ^= 0xff
	packet.Attributes.Set(radiusTypeMessageAuthenticator, attr)
	if err := verifyMessageAuthenticator(packet, secret); err == nil {
		t.Fatalf("expected verification failure")
	}

	zeroPacket := radiuslib.New(radiuslib.CodeAccessRequest, secret)
	zeroPacket.Attributes.Set(radiusTypeMessageAuthenticator, make([]byte, md5.Size))
	if !messageAuthenticatorAllZeros(zeroPacket) {
		t.Fatalf("expected zeroed message authenticator")
	}
}
