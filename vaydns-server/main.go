// vaydns-server is the server end of a DNS tunnel.
//
// Usage:
//
//	vaydns-server -udp ADDR -domain DOMAIN -upstream UPSTREAMADDR
//
// Example:
//
//	vaydns-server -udp :53 -domain t.example.com -upstream 127.0.0.1:8000
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// The -domain option specifies the root of the DNS zone reserved for the
// tunnel. See README for instructions on setting it up.
//
// The -upstream option specifies the TCP address to which incoming tunnelled
// streams will be forwarded.
package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
	"github.com/net2share/vaydns/udpaddr"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	defaultIdleTimeout = 10 * time.Second
	defaultKeepAlive   = 2 * time.Second
	// Keep this comfortably below the default client UDP response timeout and
	// low enough for interactive traffic. Long batching delays are acceptable
	// for bulk transfer but make chat and proxy workloads feel broken.
	defaultResponseDelay     = 500 * time.Millisecond
	defaultResponseWorkers   = 3
	defaultResponseQueueSize = 0

	// Default TTL for Answer resource records.
	responseTTL = 60

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second

	// Limit how many streams can be dialing upstream at once.
	upstreamDialConcurrency = 64

	// pollMarker is a reserved upstream length byte that marks an empty poll.
	// Data packets always have a positive length.
	pollMarker = 0

	// pollNonceLen is the number of cache-busting random bytes that follow a
	// poll marker. The server ignores these bytes.
	pollNonceLen = 4
)

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8

	// recordType is the DNS record type used for downstream data encoding.
	// Set from the -record-type command-line flag.
	recordType uint16 = dns.RRTypeNULL
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ServerStats tracks query processing statistics.
type ServerStats struct {
	total           uint64
	success         uint64
	responseDropped uint64
}

func (s *ServerStats) incTotal()           { atomic.AddUint64(&s.total, 1) }
func (s *ServerStats) incSuccess()         { atomic.AddUint64(&s.success, 1) }
func (s *ServerStats) incResponseDropped() { atomic.AddUint64(&s.responseDropped, 1) }
func (s *ServerStats) log() {
	total := atomic.LoadUint64(&s.total)
	success := atomic.LoadUint64(&s.success)
	responseDropped := atomic.LoadUint64(&s.responseDropped)
	log.Infof("queries: %d total, %d answered, %d dropped (response queue full)", total, success, responseDropped)
}

type idleDeadlineConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	if c.idleTimeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Read(p)
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	if c.idleTimeout > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Write(p)
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32, idleTimeout time.Duration, upstreamDialSem chan struct{}) error {
	upstreamDialSem <- struct{}{}
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	<-upstreamDialSem
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)
	if err := upstreamTCPConn.SetNoDelay(true); err != nil {
		log.Debugf("[%08x:%d] failed to set TCP_NODELAY on upstream connection: %v", conv, stream.ID(), err)
	}

	streamConn := &idleDeadlineConn{
		Conn:        stream,
		idleTimeout: idleTimeout,
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(streamConn, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("[%08x:%d] upstream -> client copy error: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, streamConn)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("[%08x:%d] client -> upstream copy error: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in an smux.Session, then awaits smux
// streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, upstream string, idleTimeout time.Duration, keepAlive time.Duration, upstreamDialSem chan struct{}) error {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = keepAlive
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	smuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024
	sess, err := smux.Server(conn, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Infof("[%08x:%d] stream opened", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Debugf("[%08x:%d] stream closed", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv(), idleTimeout, upstreamDialSem)
			if err != nil {
				log.Warnf("[%08x:%d] stream error: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, mtu int, upstream string, idleTimeout time.Duration, keepAlive time.Duration, kcpWindowSize int, upstreamDialSem chan struct{}) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Infof("[%08x] new client session established", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Keep the congestion window disabled, but otherwise stay on KCP's
		// conservative timing. The DNS layer itself is the real pacing
		// bottleneck on shutdown paths; pushing KCP harder mostly creates
		// extra churn.
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetWindowSize(kcpWindowSize, kcpWindowSize)
		if rc := conn.SetMtu(mtu); !rc {
			log.Warnf("[%08x] failed to set MTU %d, dropping session", conn.GetConv(), mtu)
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				log.Debugf("[%08x] session closed", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, upstream, idleTimeout, keepAlive, upstreamDialSem)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Warnf("[%08x] session lost: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r using the VayDNS
// wire format. It returns io.EOF only when there were 0 bytes remaining to
// read from r. It returns io.ErrUnexpectedEOF when EOF occurs in the middle
// of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	p := make([]byte, int(prefix))
	_, err = io.ReadFull(r, p)
	return p, eof(err)
}

// decodeUpstreamQuery extracts the ClientID and, for data queries, the single
// upstream packet contained in payload. Empty polls are marked by a zero byte
// followed by 4 random nonce bytes and return a nil packet.
func decodeUpstreamQuery(payload []byte, clientIDSize int) (turbotunnel.ClientID, []byte, error) {
	if len(payload) < clientIDSize {
		return "", nil, io.ErrUnexpectedEOF
	}

	clientID := turbotunnel.ClientID(string(payload[:clientIDSize]))
	payload = payload[clientIDSize:]
	if len(payload) == 0 {
		return clientID, nil, io.ErrUnexpectedEOF
	}
	if payload[0] == pollMarker {
		if len(payload) != 1+pollNonceLen {
			return clientID, nil, io.ErrUnexpectedEOF
		}
		return clientID, nil, nil
	}

	packet, err := nextPacket(bytes.NewReader(payload))
	if err != nil {
		return clientID, nil, err
	}
	if len(payload) != 1+len(packet) {
		return clientID, nil, io.ErrUnexpectedEOF
	}
	return clientID, packet, nil
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for carrying downstream data in the configured
// DNS record type.
func responseFor(query *dns.Message, domain dns.Name, addr net.Addr) (*dns.Message, []byte) {
	responsePayloadSize := uint16(maxUDPPayload)
	if int(responsePayloadSize) != maxUDPPayload {
		responsePayloadSize = 0xffff
	}

	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Debugf("rejected query from %s: more than one OPT RR", addr)
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: responsePayloadSize, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Debugf("rejected query from %s: unsupported EDNS version %d", addr, version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Debugf("rejected query from %s: expected 1 question, got %d", addr, len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Debugf("rejected query from %s: not authoritative for %s", addr, question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Debugf("rejected query from %s: unsupported opcode %d", addr, query.Opcode())
		return resp, nil
	}

	if question.Type != recordType {
		// We only support the configured QTYPE.
		resp.Flags |= dns.RcodeNameError
		// No log message here; it's common for recursive resolvers to send
		// NS or A queries when the client only asked for a different record
		// type. I suspect this is related to QNAME minimization, but I'm not
		// sure. https://tools.ietf.org/html/rfc7816
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		log.Debugf("rejected query from %s: payload is not valid base32: %v", addr, err)
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Debugf("rejected query from %s: advertised UDP payload size %d is below minimum %d", addr, payloadSize, maxUDPPayload)
		return resp, nil
	}

	return resp, payload
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
	IsPoll   bool
}

func enqueueResponse(ch chan *record, rec *record) {
	ch <- rec
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts the packets they contain on ttConn's
// incoming queue. Queries that need a response are forwarded to sendLoop over a
// blocking channel so accepted DNS queries are never silently dropped.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan *record, stats *ServerStats, wireConfig turbotunnel.WireConfig) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Warnf("transient read error on DNS socket: %v", err)
				continue
			}
			return err
		}

		stats.incTotal()

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Debugf("dropped malformed packet from %s: %v", addr, err)
			continue
		}

		resp, payload := responseFor(&query, domain, addr)
		clientID, packet, err := decodeUpstreamQuery(payload, wireConfig.ClientIDSize)
		isPoll := err == nil && packet == nil
		if err != nil {
			// Payload is not long enough to contain a ClientID.
			if errors.Is(err, io.ErrUnexpectedEOF) && len(payload) < wireConfig.ClientIDSize && resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Debugf("rejected query from %s: payload too short to contain a client ID (%d bytes)", addr, len(payload))
			}
		} else if packet != nil {
			// Feed the incoming packet to KCP.
			ttConn.QueueIncoming(packet, clientID)
		}
		// If a response is called for, pass it to the shared response loop.
		if resp != nil {
			if resp.Rcode() == dns.RcodeNoError {
				stats.incSuccess()
			}
			enqueueResponse(ch, &record{resp, addr, clientID, isPoll})
		}
	}
}

// encodeResponsePayload encodes the downstream payload into the DNS response
// Answer section using the record type from the query's Question.
func encodeResponsePayload(rec *record, data []byte, domain dns.Name) error {
	qtype := rec.Resp.Question[0].Type
	switch qtype {
	case dns.RRTypeA, dns.RRTypeAAAA:
		var chunks [][]byte
		if qtype == dns.RRTypeA {
			chunks = dns.EncodeRDataA(data)
		} else {
			chunks = dns.EncodeRDataAAAA(data)
		}
		rec.Resp.Answer = make([]dns.RR, len(chunks))
		for i, chunk := range chunks {
			rec.Resp.Answer[i] = dns.RR{
				Name:  rec.Resp.Question[0].Name,
				Type:  qtype,
				Class: rec.Resp.Question[0].Class,
				TTL:   responseTTL,
				Data:  chunk,
			}
		}
	case dns.RRTypeNULL:
		rec.Resp.Answer[0].Data = dns.EncodeRDataNULL(data)
	case dns.RRTypeHINFO:
		rec.Resp.Answer[0].Data = dns.EncodeRDataHINFO(data)
	case dns.RRTypeCAA:
		rec.Resp.Answer[0].Data = dns.EncodeRDataCAA(data)
	case dns.RRTypeCERT:
		rec.Resp.Answer[0].Data = dns.EncodeRDataCERT(data)
	case dns.RRTypeCNAME:
		rdata, err := dns.EncodeRDataCNAME(data, domain)
		if err != nil {
			return fmt.Errorf("EncodeRDataCNAME: %w", err)
		}
		rec.Resp.Answer[0].Data = rdata
	case dns.RRTypeNS:
		rdata, err := dns.EncodeRDataNS(data, domain)
		if err != nil {
			return fmt.Errorf("EncodeRDataNS: %w", err)
		}
		rec.Resp.Answer[0].Data = rdata
	case dns.RRTypeMX:
		rdata, err := dns.EncodeRDataMX(data, domain)
		if err != nil {
			return fmt.Errorf("EncodeRDataMX: %w", err)
		}
		rec.Resp.Answer[0].Data = rdata
	case dns.RRTypeSRV:
		rdata, err := dns.EncodeRDataSRV(data, domain)
		if err != nil {
			return fmt.Errorf("EncodeRDataSRV: %w", err)
		}
		rec.Resp.Answer[0].Data = rdata
	case dns.RRTypeHTTPS:
		rdata, err := dns.EncodeRDataHTTPS(data, domain)
		if err != nil {
			return fmt.Errorf("EncodeRDataHTTPS: %w", err)
		}
		rec.Resp.Answer[0].Data = rdata
	default:
		rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(data)
	}
	return nil
}

func writeResponse(dnsConn net.PacketConn, rec *record, writeMu *sync.Mutex) {
	buf, err := rec.Resp.WireFormat()
	if err != nil {
		log.Errorf("failed to serialize DNS response: %v", err)
		return
	}
	if len(buf) > maxUDPPayload {
		log.Warnf("response too large (%d bytes), sending TC=1 truncated response", len(buf))
		rec.Resp.Flags |= 0x0200 // TC = 1
		rec.Resp.Answer = nil
		rec.Resp.Authority = nil
		buf, err = rec.Resp.WireFormat()
		if err != nil {
			log.Errorf("failed to serialize truncated DNS response: %v", err)
			return
		}
		if len(buf) > maxUDPPayload {
			rec.Resp.Additional = nil
			buf, err = rec.Resp.WireFormat()
			if err != nil {
				log.Errorf("failed to serialize minimal truncated DNS response: %v", err)
				return
			}
			if len(buf) > maxUDPPayload {
				log.Errorf("minimal truncated DNS response still exceeds UDP payload limit: %d > %d", len(buf), maxUDPPayload)
				return
			}
		}
	}

	writeMu.Lock()
	_, err = dnsConn.WriteTo(buf, rec.Addr)
	writeMu.Unlock()
	if err != nil {
		log.Warnf("failed to send DNS response to %s: %v", rec.Addr, err)
	}
}

func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int, responseDelay time.Duration, domain dns.Name, writeMu *sync.Mutex) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				return nil
			}
		}

	if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
		rec.Resp.Answer = []dns.RR{
			{
				Name:  rec.Resp.Question[0].Name,
				Type:  rec.Resp.Question[0].Type,
				Class: rec.Resp.Question[0].Class,
				TTL:   responseTTL,
				Data:  nil,
			},
		}

		var payload bytes.Buffer
		limit := maxEncodedPayload
		waitDelay := responseDelay
		if rec.IsPoll {
			waitDelay = 0
		}

		timer := time.NewTimer(waitDelay)
		for {
			var p []byte
			unstash := ttConn.Unstash(rec.ClientID)
			outgoing := ttConn.OutgoingQueue(rec.ClientID)
			select {
			case p = <-unstash:
			default:
				select {
				case p = <-unstash:
				case p = <-outgoing:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					case <-timer.C:
					case nextRec = <-ch:
					}
				}
			}
			timer.Reset(0)

			if len(p) == 0 {
				break
			}

			limit -= 2 + len(p)
			if payload.Len() > 0 && limit < 0 {
				ttConn.Stash(p, rec.ClientID)
				break
			}
			if int(uint16(len(p))) != len(p) {
				panic(len(p))
			}
			binary.Write(&payload, binary.BigEndian, uint16(len(p)))
			payload.Write(p)
		}
		timer.Stop()

		if err := encodeResponsePayload(rec, payload.Bytes(), domain); err != nil {
			log.Errorf("failed to encode downstream payload: %v", err)
			continue
		}
	}

	writeResponse(dnsConn, rec, writeMu)
	}
}

// computeMaxEncodedPayload computes the maximum amount of downstream single-RR
// payload that keeps the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int, encode func([]byte) []byte) int {
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  recordType,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, dns.Name([][]byte{}), nil)
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = encode(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

// computeMaxEncodedPayloadNameBased computes the maximum raw payload bytes that
// can fit in a name-based RDATA (CNAME, NS, MX, SRV, HTTPS). The capacity is the same
// for all name-based types because it is constrained by the 255-byte DNS name
// limit, not the UDP payload size. The MX/SRV/HTTPS fixed headers (2/6/2 bytes)
// add to the total RDATA but do not reduce the name portion.
func computeMaxEncodedPayloadNameBased(domain dns.Name) int {
	domainWireLen := 1 // null terminator
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}
	available := 255 - domainWireLen
	if available <= 0 {
		return 0
	}
	encodedBytes := available * 63 / 64
	return encodedBytes * 5 / 8
}

// computeMaxEncodedPayloadMultiRR computes the maximum raw payload bytes that
// can fit in multiple fixed-size RRs (A=4 bytes, AAAA=16 bytes) within a DNS
// response of at most limit bytes. Each RR carries a 2-byte [index,total]
// header, so the payload portion per RR is chunkSize-2 bytes.
func computeMaxEncodedPayloadMultiRR(limit int, chunkSize int) int {
	if chunkSize <= 2 {
		panic("chunkSize must be greater than 2")
	}
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  recordType,
				Class: dns.ClassIN,
			},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, dns.Name([][]byte{}), nil)

	// Binary search: find max payload that fits when split into chunkSize RRs.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		// Simulate encoding: 2-byte length prefix + payload -> ceil((2+mid)/(chunkSize-2)) RRs.
		totalBytes := 2 + mid
		payloadPerChunk := chunkSize - 2
		numChunks := (totalBytes + payloadPerChunk - 1) / payloadPerChunk
		resp.Answer = make([]dns.RR, numChunks)
		for i := range numChunks {
			resp.Answer[i] = dns.RR{
				Name:  query.Question[0].Name,
				Type:  query.Question[0].Type,
				Class: query.Question[0].Class,
				TTL:   responseTTL,
				Data:  make([]byte, chunkSize),
			}
		}
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

func run(domain dns.Name, upstream string, dnsConn net.PacketConn, idleTimeout time.Duration, keepAlive time.Duration, queueSize int, kcpWindowSize int, queueOverflowMode turbotunnel.QueueOverflowMode, responseQueueSize int, responseWorkers int, responseDelay time.Duration, wireConfig turbotunnel.WireConfig) error {
	defer dnsConn.Close()

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	var maxEncodedPayload int
	switch recordType {
	case dns.RRTypeCNAME, dns.RRTypeNS, dns.RRTypeMX, dns.RRTypeSRV, dns.RRTypeHTTPS:
		maxEncodedPayload = computeMaxEncodedPayloadNameBased(domain)
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
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Infof("effective tunnel MTU: %d bytes", mtu)

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2, queueSize, queueOverflowMode)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()
	upstreamDialSem := make(chan struct{}, upstreamDialConcurrency)
	go func() {
		err := acceptSessions(ln, mtu, upstream, idleTimeout, keepAlive, kcpWindowSize, upstreamDialSem)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("KCP listener stopped accepting sessions: %v", err)
		}
	}()

	if responseQueueSize <= 0 {
		responseQueueSize = queueSize
	}
	if responseWorkers <= 0 {
		responseWorkers = defaultResponseWorkers
	}
	if responseDelay <= 0 {
		responseDelay = defaultResponseDelay
	}

	var writeMu sync.Mutex
	ch := make(chan *record, responseQueueSize)
	shutdown := make(chan struct{})
	defer close(ch)
	defer close(shutdown)

	stats := &ServerStats{}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stats.log()
			case <-shutdown:
				return
			}
		}
	}()

	for i := 0; i < responseWorkers; i++ {
		go func() {
			for {
				err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload, responseDelay, domain, &writeMu)
				if err == nil {
					return
				}
				if errors.Is(err, net.ErrClosed) {
					select {
					case <-shutdown:
						return
					case <-time.After(time.Second):
					}
					continue
				}
				log.Warnf("response sender exited: %v", err)
				select {
				case <-shutdown:
					return
				case <-time.After(time.Second):
				}
			}
		}()
	}

	return recvLoop(domain, dnsConn, ttConn, ch, stats, wireConfig)
}

var version = "dev"

func main() {
	var showVersion bool
	var domainArg string
	var upstream string
	var udpAddr string
	var idleTimeoutStr string
	var keepAliveStr string
	var clientIDSize int
	var recordTypeStr string
	var queueSize int
	var kcpWindowSize int
	var queueOverflowStr string
	var responseQueueSize int
	var responseWorkers int
	var responseDelayStr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -udp ADDR -domain DOMAIN -upstream UPSTREAMADDR

Example:
  %[1]s -udp :53 -domain t.example.com -upstream 127.0.0.1:8000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (required)")
	flag.StringVar(&domainArg, "domain", "", "tunnel domain (e.g., t.example.com)")
	flag.StringVar(&upstream, "upstream", "127.0.0.1:10888", "TCP address to forward tunneled connections to (default 127.0.0.1:10888)")
	// idle-timeout: if no data is received from a client for this long,
	// the tunnel session is considered dead and torn down. Should match
	// the client's -idle-timeout.
	flag.StringVar(&idleTimeoutStr, "idle-timeout", defaultIdleTimeout.String(), "session idle timeout (e.g. 10s, 1m); tears down sessions with no data within this period")
	// keepalive: how often smux sends keepalive pings. Must be shorter than
	// idle-timeout. Should match the client's -keepalive value.
	flag.StringVar(&keepAliveStr, "keepalive", defaultKeepAlive.String(), "keepalive ping interval (e.g. 2s, 1s); must be less than idle-timeout")
	flag.IntVar(&clientIDSize, "clientid-size", 1, "client ID size in bytes")
	flag.StringVar(&recordTypeStr, "record-type", "null", "DNS record type for downstream data (txt, null, hinfo, cname, a, aaaa, mx, ns, srv, cert, https, caa)")
	flag.IntVar(&queueSize, "queue-size", turbotunnel.QueueSize, "packet queue size for DNS tunnel transport")
	flag.IntVar(&kcpWindowSize, "kcp-window-size", 0, "KCP send/receive window size in packets (0 = queue-size/2)")
	flag.StringVar(&queueOverflowStr, "queue-overflow", string(turbotunnel.DefaultQueueOverflowMode), "queue overflow behavior: drop or block")
	flag.IntVar(&responseQueueSize, "response-queue-size", defaultResponseQueueSize, "pending DNS response queue size (0 = queue-size)")
	flag.IntVar(&responseWorkers, "response-workers", defaultResponseWorkers, "number of DNS response sender workers")
	flag.StringVar(&responseDelayStr, "response-delay", defaultResponseDelay.String(), "maximum time to hold a DNS response open for downstream data (e.g. 200ms, 500ms)")

	var logLevel string
	flag.StringVar(&logLevel, "log-level", "info", "log level (debug, info, warning, error)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %s\n", logLevel)
		os.Exit(1)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05"})

	rt, err := dns.ParseRecordType(recordTypeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	recordType = rt

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments\n")
		flag.Usage()
		os.Exit(1)
	}
	if domainArg == "" {
		fmt.Fprintf(os.Stderr, "the -domain option is required\n")
		os.Exit(1)
	}
	domain, err := dns.ParseName(domainArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", domainArg, err)
		os.Exit(1)
	}
	// We keep upstream as a string in order to eventually pass it
	// to net.Dial in handleStream. But for the sake of displaying
	// an error or warning at startup, rather than only when the
	// first stream occurs, we apply some parsing and name
	// resolution checks here.
	{
		upstreamHost, _, err := net.SplitHostPort(upstream)
		if err != nil {
			// host:port format is required in all cases, so
			// this is a fatal error.
			fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: %v\n", upstream, err)
			os.Exit(1)
		}
		upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
		if err != nil {
			// Failure to resolve the host portion is only a
			// warning. The name will be re-resolved on each
			// net.Dial in handleStream.
			log.Warnf("upstream host %q could not be resolved at startup, will retry on first connection: %v", upstreamHost, err)
		} else if upstreamIPAddr.IP == nil {
			// Handle the special case of an empty string
			// for the host portion, which resolves to a nil
			// IP. This is a fatal error as we will not be
			// able to dial this address.
			fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: missing host in address\n", upstream)
			os.Exit(1)
		}
	}

	if udpAddr == "" {
		fmt.Fprintf(os.Stderr, "the -udp option is required\n")
		os.Exit(1)
	}
	udpAddr, err = udpaddr.Normalize(udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp: %v\n", err)
		os.Exit(1)
	}
	dnsConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "opening UDP listener: %v\n", err)
		os.Exit(1)
	}

	idleTimeout, err := time.ParseDuration(idleTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -idle-timeout: %v\n", err)
		os.Exit(1)
	}
	keepAlive, err := time.ParseDuration(keepAliveStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -keepalive: %v\n", err)
		os.Exit(1)
	}
	responseDelay, err := time.ParseDuration(responseDelayStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -response-delay: %v\n", err)
		os.Exit(1)
	}
	if keepAlive >= idleTimeout {
		fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
		os.Exit(1)
	}
	if queueSize < 32 {
		fmt.Fprintf(os.Stderr, "-queue-size (%d) must be at least 32\n", queueSize)
		os.Exit(1)
	}
	if kcpWindowSize < 0 {
		fmt.Fprintf(os.Stderr, "-kcp-window-size (%d) must be >= 0\n", kcpWindowSize)
		os.Exit(1)
	}
	if kcpWindowSize == 0 {
		kcpWindowSize = queueSize / 2
		if kcpWindowSize < 1 {
			kcpWindowSize = 1
		}
	}
	if kcpWindowSize > queueSize {
		fmt.Fprintf(os.Stderr, "-kcp-window-size (%d) must be <= -queue-size (%d)\n", kcpWindowSize, queueSize)
		os.Exit(1)
	}
	if responseQueueSize < 0 {
		fmt.Fprintf(os.Stderr, "-response-queue-size (%d) must be >= 0\n", responseQueueSize)
		os.Exit(1)
	}
	if responseWorkers <= 0 {
		fmt.Fprintf(os.Stderr, "-response-workers (%d) must be greater than 0\n", responseWorkers)
		os.Exit(1)
	}
	if responseDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-response-delay (%s) must be greater than 0\n", responseDelay)
		os.Exit(1)
	}
	queueOverflowMode, err := turbotunnel.ParseQueueOverflowMode(queueOverflowStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -queue-overflow: %v\n", err)
		os.Exit(1)
	}
	if clientIDSize <= 0 {
		fmt.Fprintf(os.Stderr, "-clientid-size must be positive\n")
		os.Exit(1)
	}
	wireConfig := turbotunnel.WireConfig{ClientIDSize: clientIDSize}

	switch recordType {
	case dns.RRTypeCNAME, dns.RRTypeNS, dns.RRTypeMX, dns.RRTypeSRV, dns.RRTypeHTTPS:
		explicitFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) {
			explicitFlags[f.Name] = true
		})
		if explicitFlags["mtu"] {
			log.Warnf("-mtu is ignored for record type %s - payload capacity is bounded by the DNS name length limit (255 bytes)", recordTypeStr)
		}
	}

	err = run(domain, upstream, dnsConn, idleTimeout, keepAlive, queueSize, kcpWindowSize, queueOverflowMode, responseQueueSize, responseWorkers, responseDelay, wireConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
