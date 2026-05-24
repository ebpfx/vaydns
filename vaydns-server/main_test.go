package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/net2share/vaydns/dns"
)

func allServerPackets(buf []byte) ([][]byte, error) {
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

func TestNextPacket(t *testing.T) {
	for _, test := range []struct {
		input   string
		packets [][]byte
		err     error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{{}}, io.EOF},
		{"\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x05hello\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
		{"\x05hello\x05worl", [][]byte{[]byte("hello")}, io.ErrUnexpectedEOF},
	} {
		packets, err := allServerPackets([]byte(test.input))
		if len(packets) != len(test.packets) || err != test.err {
			t.Fatalf("%x returned %x %v, expected %x %v", test.input, packets, err, test.packets, test.err)
		}
		for i := range packets {
			if !bytes.Equal(packets[i], test.packets[i]) {
				t.Fatalf("%x returned %x %v, expected %x %v", test.input, packets, err, test.packets, test.err)
			}
		}
	}
}

func TestDecodeUpstreamQueryData(t *testing.T) {
	clientID, packet, err := decodeUpstreamQuery([]byte{0xaa, 0xbb, 0x03, 'a', 'b', 'c'}, 2)
	if err != nil {
		t.Fatalf("decodeUpstreamQuery: %v", err)
	}
	if got, want := []byte(clientID), []byte{0xaa, 0xbb}; !bytes.Equal(got, want) {
		t.Fatalf("client ID = %x, want %x", got, want)
	}
	if got, want := packet, []byte("abc"); !bytes.Equal(got, want) {
		t.Fatalf("packet = %x, want %x", got, want)
	}
}

func TestDecodeUpstreamQueryPoll(t *testing.T) {
	clientID, packet, err := decodeUpstreamQuery([]byte{0xaa, 0xbb, 0x00, 0x01, 0x02, 0x03, 0x04}, 2)
	if err != nil {
		t.Fatalf("decodeUpstreamQuery: %v", err)
	}
	if got, want := []byte(clientID), []byte{0xaa, 0xbb}; !bytes.Equal(got, want) {
		t.Fatalf("client ID = %x, want %x", got, want)
	}
	if packet != nil {
		t.Fatalf("packet = %x, want nil", packet)
	}
}

func TestDecodeUpstreamQueryRejectsMalformedPoll(t *testing.T) {
	if _, _, err := decodeUpstreamQuery([]byte{0xaa, 0xbb, 0x00, 0x01, 0x02}, 2); err != io.ErrUnexpectedEOF {
		t.Fatalf("decodeUpstreamQuery error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestComputeMaxEncodedPayloadNameBasedAccountsForRootLabel(t *testing.T) {
	domain := dns.Name{bytes.Repeat([]byte{'a'}, 63)}
	if got, want := computeMaxEncodedPayloadNameBased(domain), 116; got != want {
		t.Fatalf("computeMaxEncodedPayloadNameBased = %d, want %d", got, want)
	}
}

func TestRecordTypeMaxEncodedPayloadHINFO(t *testing.T) {
	prevRecordType := recordType
	defer func() { recordType = prevRecordType }()
	recordType = dns.RRTypeHINFO
	var maxEncodedPayload int
	switch recordType {
	case dns.RRTypeCNAME, dns.RRTypeNS, dns.RRTypeMX, dns.RRTypeSRV, dns.RRTypeHTTPS:
		maxEncodedPayload = computeMaxEncodedPayloadNameBased(dns.Name([][]byte{}))
	case dns.RRTypeA:
		maxEncodedPayload = computeMaxEncodedPayloadMultiRR(maxUDPPayload, 4)
	case dns.RRTypeAAAA:
		maxEncodedPayload = computeMaxEncodedPayloadMultiRR(maxUDPPayload, 16)
	case dns.RRTypeNULL:
		maxEncodedPayload = computeMaxEncodedPayload(maxUDPPayload, dns.EncodeRDataNULL)
	case dns.RRTypeHINFO:
		maxEncodedPayload = 510
	case dns.RRTypeCAA:
		maxEncodedPayload = computeMaxEncodedPayload(maxUDPPayload, dns.EncodeRDataCAA)
	case dns.RRTypeCERT:
		maxEncodedPayload = computeMaxEncodedPayload(maxUDPPayload, dns.EncodeRDataCERT)
	default:
		maxEncodedPayload = computeMaxEncodedPayload(maxUDPPayload, dns.EncodeRDataTXT)
	}
	if got, want := maxEncodedPayload, 510; got != want {
		t.Fatalf("maxEncodedPayload for HINFO = %d, want %d", got, want)
	}
}
