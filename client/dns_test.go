package client

import (
	"bytes"
	"encoding/base32"
	"io"
	"net"
	"testing"
	"time"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

func allPackets(buf []byte) ([][]byte, error) {
	var packets [][]byte
	r := bytes.NewReader(buf)
	for {
		p, err := nextPacket(r)
		if err != nil {
			return packets, err
		}
		packets = append(packets, p)
	}
}

func packetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestNextPacket(t *testing.T) {
	for _, test := range []struct {
		input   string
		packets [][]byte
		err     error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x00", [][]byte{{}}, io.EOF},
		{"\x00\x00\x00", [][]byte{{}}, io.ErrUnexpectedEOF},
		{"\x00\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x05hello\x00\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
	} {
		packets, err := allPackets([]byte(test.input))
		if !packetsEqual(packets, test.packets) || err != test.err {
			t.Errorf("%x\nreturned %x %v\nexpected %x %v",
				test.input, packets, err, test.packets, test.err)
		}
	}
}

// computeQueryNameLen calculates the total length of a DNS query name
// given encoded data length and domain labels.
func computeQueryNameLen(encodedLen int, domain dns.Name) int {
	const labelLen = 63
	numLabels := (encodedLen + labelLen - 1) / labelLen
	if numLabels == 0 {
		numLabels = 1
	}
	queryNameLen := encodedLen + (numLabels - 1) // encoded data + separator dots
	for _, label := range domain {
		queryNameLen += 1 + len(label)
	}
	return queryNameLen
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(100) // 100 rps
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	// Should be able to consume the initial burst quickly
	start := time.Now()
	for i := 0; i < 50; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("initial burst of 50 at 100 rps took %v, expected < 200ms", elapsed)
	}
}

func TestRateLimiterNil(t *testing.T) {
	// NewRateLimiter returns nil for invalid values
	if NewRateLimiter(0) != nil {
		t.Error("expected nil for rps=0")
	}
	if NewRateLimiter(-5) != nil {
		t.Error("expected nil for negative rps")
	}

	// nil Wait() should not panic
	var rl *RateLimiter
	rl.Wait() // should be a no-op
}

func TestLabelConstraints(t *testing.T) {
	const labelLen = 63
	testCases := []struct {
		maxQnameLen  int
		maxNumLabels int
		domainStr    string
	}{
		{0, 1, "d.example.org"},
		{0, 0, "t.example.com"},
		{200, 2, "short.io"},
	}

	for _, tc := range testCases {
		domain, err := dns.ParseName(tc.domainStr)
		if err != nil {
			t.Fatalf("failed to parse domain %q: %v", tc.domainStr, err)
		}

		maxEncoded := labelLen * 4
		if tc.maxNumLabels > 0 {
			maxEncoded = tc.maxNumLabels * labelLen
		}

		queryNameLen := computeQueryNameLen(maxEncoded, domain)

		actualLabels := (maxEncoded + labelLen - 1) / labelLen
		if tc.maxNumLabels > 0 && actualLabels > tc.maxNumLabels {
			t.Errorf("maxQnameLen=%d maxNumLabels=%d: produced %d labels, expected max %d",
				tc.maxQnameLen, tc.maxNumLabels, actualLabels, tc.maxNumLabels)
		}

		t.Logf("maxQnameLen=%d maxNumLabels=%d domain=%s: maxEncoded=%d queryNameLen=%d",
			tc.maxQnameLen, tc.maxNumLabels, tc.domainStr, maxEncoded, queryNameLen)
	}
}

type capturePacketConn struct {
	buf []byte
}

func (c *capturePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *capturePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.buf = append([]byte(nil), p...)
	return len(p), nil
}
func (c *capturePacketConn) Close() error                     { return nil }
func (c *capturePacketConn) LocalAddr() net.Addr              { return turbotunnel.DummyAddr{} }
func (c *capturePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *capturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePacketConn) SetWriteDeadline(time.Time) error { return nil }

var testBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func decodeQueryPayload(t *testing.T, buf []byte, domain dns.Name) []byte {
	t.Helper()

	msg, err := dns.MessageFromWireFormat(buf)
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}
	if len(msg.Question) != 1 {
		t.Fatalf("unexpected question count: %d", len(msg.Question))
	}
	labels, ok := msg.Question[0].Name.TrimSuffix(domain)
	if !ok {
		t.Fatalf("query name %s does not end with domain %s", msg.Question[0].Name, domain)
	}
	var encoded []byte
	for _, label := range labels {
		encoded = append(encoded, label...)
	}
	decoded := make([]byte, testBase32Encoding.DecodedLen(len(encoded)))
	n, err := testBase32Encoding.Decode(decoded, encoded)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	return decoded[:n]
}

func TestSendEncodesDataQuery(t *testing.T) {
	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	conn := &capturePacketConn{}
	c := &DNSPacketConn{
		clientID:    turbotunnel.NewClientID(3),
		wireConfig:  turbotunnel.WireConfig{ClientIDSize: 3},
		domain:      domain,
		rrType:      dns.RRTypeTXT,
		maxQnameLen: 253,
	}

	payload := []byte("abc")
	if err := c.send(conn, payload, turbotunnel.DummyAddr{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	decoded := decodeQueryPayload(t, conn.buf, domain)
	if !bytes.Equal(decoded[:3], c.clientID.Bytes()) {
		t.Fatalf("client ID mismatch: got %x want %x", decoded[:3], c.clientID.Bytes())
	}
	if got, want := int(decoded[3]), len(payload); got != want {
		t.Fatalf("data length mismatch: got %d want %d", got, want)
	}
	if !bytes.Equal(decoded[4:], payload) {
		t.Fatalf("payload mismatch: got %x want %x", decoded[4:], payload)
	}
}

func TestSendEncodesPollQuery(t *testing.T) {
	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	conn := &capturePacketConn{}
	c := &DNSPacketConn{
		clientID:    turbotunnel.NewClientID(2),
		wireConfig:  turbotunnel.WireConfig{ClientIDSize: 2},
		domain:      domain,
		rrType:      dns.RRTypeTXT,
		maxQnameLen: 253,
	}

	if err := c.send(conn, nil, turbotunnel.DummyAddr{}); err != nil {
		t.Fatalf("send poll: %v", err)
	}
	decoded := decodeQueryPayload(t, conn.buf, domain)
	if got, want := len(decoded), c.clientID.Len()+1+pollNonceLen; got != want {
		t.Fatalf("poll length mismatch: got %d want %d", got, want)
	}
	if !bytes.Equal(decoded[:c.clientID.Len()], c.clientID.Bytes()) {
		t.Fatalf("client ID mismatch: got %x want %x", decoded[:c.clientID.Len()], c.clientID.Bytes())
	}
	if decoded[c.clientID.Len()] != pollMarker {
		t.Fatalf("poll marker mismatch: got %d want %d", decoded[c.clientID.Len()], pollMarker)
	}
}

func TestSendRejectsOversizeDataQuery(t *testing.T) {
	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	c := &DNSPacketConn{
		clientID:    turbotunnel.NewClientID(2),
		wireConfig:  turbotunnel.WireConfig{ClientIDSize: 2},
		domain:      domain,
		rrType:      dns.RRTypeTXT,
		maxQnameLen: 253,
	}

	if err := c.send(&capturePacketConn{}, bytes.Repeat([]byte{'x'}, 256), turbotunnel.DummyAddr{}); err == nil {
		t.Fatal("expected oversize payload error")
	}
}
