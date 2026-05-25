package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

const (
	// pollMarker is a reserved length byte for empty polls. Data packets
	// always have a positive length.
	pollMarker = 0

	// pollNonceLen is the number of random bytes appended to poll queries
	// for cache busting. Without this, empty polls would be identical and
	// recursive resolvers would return cached (stale) responses.
	pollNonceLen = 4

	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer starts at pollDelay, increases by pollDelayMultiplier on
	// idle expirations, and is capped at pollMaxDelay. When there are
	// active tunnel streams, we instead use activePollDelay both as the
	// reset value and as the cap so downstream data keeps flowing quickly.
	pollDelayMultiplier = 2.0

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data.
	pollLimit = 16
)

// base32Encoding is a base32 encoding without padding, using lowercase
// characters to avoid a separate conversion step. DNS is case-insensitive,
// but lowercase is less likely to stand out in logs.
var base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// forgedInfoMilestones defines the exact totals at which an INFO log is
// emitted. After the last explicit milestone the interval logic in
// forgedInfoMilestone takes over.
var forgedInfoMilestones = [...]uint64{10, 100, 500, 1000, 2500, 5000}

// RateLimiter implements a token bucket rate limiter for DNS queries.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// NewRateLimiter creates a new token bucket rate limiter with the given
// queries-per-second rate. Returns nil for non-positive or invalid values,
// which means unlimited.
func NewRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		return nil
	}
	capacity := rps
	if capacity < 1.0 {
		// A fractional rate still needs to be able to accumulate one whole token.
		capacity = 1.0
	}
	return &RateLimiter{
		tokens:   capacity,
		capacity: capacity,
		rate:     rps,
		lastTime: time.Now(),
	}
}

// Wait blocks until a token is available. It is safe to call on a nil receiver
// (no-op), which allows clean "unlimited" behavior without nil checks at call sites.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	for {
		rl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(rl.lastTime).Seconds()
		rl.lastTime = now
		rl.tokens += elapsed * rl.rate
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
		if rl.tokens >= 1.0 {
			rl.tokens -= 1.0
			rl.mu.Unlock()
			return
		}
		needed := 1.0 - rl.tokens
		waitTime := time.Duration(needed / rl.rate * float64(time.Second))
		rl.mu.Unlock()
		time.Sleep(waitTime)
	}
}

// ForgedStats tracks forged DNS response counters. It is shared between
// UDPPacketConn (per-query mode) and DNSPacketConn (shared socket mode) so
// that forged response visibility is consistent regardless of transport.
type ForgedStats struct {
	Total    uint64
	SERVFAIL uint64
	NXDOMAIN uint64
	Other    uint64
}

// Record increments the appropriate counter for the given RCODE and logs
// a summary at INFO level at milestone counts. Non-milestone forged
// responses are silently counted.
func (s *ForgedStats) Record(rcode uint16) {
	switch rcode {
	case dns.RcodeServerFailure:
		atomic.AddUint64(&s.SERVFAIL, 1)
	case dns.RcodeNameError:
		atomic.AddUint64(&s.NXDOMAIN, 1)
	default:
		atomic.AddUint64(&s.Other, 1)
	}
	total := atomic.AddUint64(&s.Total, 1)
	if forgedInfoMilestone(total) {
		log.Infof("forged DNS responses: total=%d, SERVFAIL=%d, NXDOMAIN=%d, other=%d",
			total,
			atomic.LoadUint64(&s.SERVFAIL),
			atomic.LoadUint64(&s.NXDOMAIN),
			atomic.LoadUint64(&s.Other))
	}
}

func forgedInfoMilestone(total uint64) bool {
	for _, m := range forgedInfoMilestones {
		if total == m {
			return true
		}
	}
	switch {
	case total <= 100_000:
		return total%10_000 == 0
	case total <= 1_000_000:
		return total%50_000 == 0
	default:
		return total%100_000 == 0
	}
}

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as an RR in
// downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, one of which must be provided to
// NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID   turbotunnel.ClientID
	wireConfig turbotunnel.WireConfig
	domain     dns.Name
	// rrType is the DNS record type used for downstream data (TXT, NULL, HINFO,
	// CNAME, A, AAAA, MX, NS, SRV, CERT, HTTPS, or CAA).
	rrType uint16
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// rateLimiter throttles outgoing DNS queries (nil = unlimited).
	rateLimiter *RateLimiter
	// maxQnameLen is the maximum total QNAME length in wire format (0 = 253 per RFC).
	maxQnameLen int
	// maxNumLabels is the maximum number of data labels (0 = unlimited).
	maxNumLabels int
	// Forged response tracking (shared with UDPPacketConn in per-query mode)
	forgedStats *ForgedStats
	// activeStreams is incremented while stream establishment or stream I/O is
	// in progress. When positive, sendLoop keeps polling aggressively instead
	// of backing off to the idle maximum.
	activeStreams   *atomic.Int32
	pollDelay       time.Duration
	activePollDelay time.Duration
	pollMaxDelay    time.Duration
	// Transport error reporting for session health monitoring
	transportErr chan error
	// lastSuccess tracks the time of the last successful response for stale detection
	lastSuccess atomic.Int64
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent.
// maxQnameLen is the max total QNAME length (0 = 253 per RFC 1035).
// maxNumLabels is the max number of data labels (0 = unlimited).
// forgedStats is shared with the transport layer (e.g. UDPPacketConn) for
// consistent forged response tracking; if nil, a new instance is created.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, rateLimiter *RateLimiter, maxQnameLen int, maxNumLabels int, wireConfig turbotunnel.WireConfig, forgedStats *ForgedStats, rrType uint16, numWorkers int, queueSize int, overflowMode turbotunnel.QueueOverflowMode) *DNSPacketConn {
	return newDNSPacketConn(transport, addr, domain, rateLimiter, maxQnameLen, maxNumLabels, wireConfig, forgedStats, rrType, nil, DefaultPollDelay, DefaultActivePollDelay, DefaultPollMaxDelay, numWorkers, queueSize, overflowMode)
}

// newDNSPacketConn is the internal constructor that can optionally receive a
// pointer to the active stream counter for stream-aware polling.
func newDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, rateLimiter *RateLimiter, maxQnameLen int, maxNumLabels int, wireConfig turbotunnel.WireConfig, forgedStats *ForgedStats, rrType uint16, activeStreams *atomic.Int32, pollDelay time.Duration, activePollDelay time.Duration, pollMaxDelay time.Duration, numWorkers int, queueSize int, overflowMode turbotunnel.QueueOverflowMode) *DNSPacketConn {
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	if pollDelay <= 0 {
		pollDelay = DefaultPollDelay
	}
	if activePollDelay <= 0 {
		activePollDelay = DefaultActivePollDelay
	}
	if pollMaxDelay <= 0 {
		pollMaxDelay = DefaultPollMaxDelay
	}
	if pollMaxDelay < pollDelay {
		pollMaxDelay = pollDelay
	}
	if forgedStats == nil {
		forgedStats = &ForgedStats{}
	}
	if numWorkers <= 0 {
		numWorkers = 1
	}
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID(wireConfig.ClientIDSize)
	if rrType == 0 {
		rrType = dns.RRTypeTXT
	}
	c := &DNSPacketConn{
		clientID:        clientID,
		wireConfig:      wireConfig,
		domain:          domain,
		rrType:          rrType,
		pollChan:        make(chan struct{}, pollLimit),
		rateLimiter:     rateLimiter,
		maxQnameLen:     maxQnameLen,
		maxNumLabels:    maxNumLabels,
		forgedStats:     forgedStats,
		activeStreams:   activeStreams,
		pollDelay:       pollDelay,
		activePollDelay: activePollDelay,
		pollMaxDelay:    pollMaxDelay,
		transportErr:    make(chan error, 2),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0, queueSize, overflowMode),
	}
	// Arm stale detection immediately so a shared UDP socket that never
	// receives a valid response can still be retired and rebuilt.
	c.markSuccess()
	go func() {
		err := c.recvLoop(transport)
		select {
		case <-c.QueuePacketConn.Closed():
			return
		default:
		}
		if err != nil {
			log.Errorf("DNS receive loop exited unexpectedly: %v", err)
			select {
			case c.transportErr <- fmt.Errorf("DNS receive loop: %w", err):
			default:
			}
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr, numWorkers)
		select {
		case <-c.QueuePacketConn.Closed():
			return
		default:
		}
		if err != nil {
			log.Errorf("DNS send loop exited unexpectedly: %v", err)
			select {
			case c.transportErr <- fmt.Errorf("DNS send loop: %w", err):
			default:
			}
		}
	}()
	return c
}

// TransportErrors returns a channel that receives errors from the
// underlying transport goroutines (recvLoop and sendLoop).
func (c *DNSPacketConn) TransportErrors() <-chan error {
	return c.transportErr
}

func (c *DNSPacketConn) markSuccess() {
	c.lastSuccess.Store(time.Now().UnixNano())
}

func (c *DNSPacketConn) lastSuccessTime() time.Time {
	ns := c.lastSuccess.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (c *DNSPacketConn) currentPollDelay() time.Duration {
	if c.activeStreams != nil && c.activeStreams.Load() > 0 {
		return c.activePollDelay
	}
	return c.pollDelay
}

func (c *DNSPacketConn) currentPollMaxDelay() time.Duration {
	if c.activeStreams != nil && c.activeStreams.Load() > 0 {
		return c.activePollDelay
	}
	return c.pollMaxDelay
}

// dnsResponsePayload extracts the downstream payload of a DNS response. It
// returns (nil, true) when the response has a non-NoError RCODE, indicating a
// forged or hijacked response. It returns (payload, false) on success or
// (nil, false) when the response doesn't pass format checks.
func dnsResponsePayload(resp *dns.Message, domain dns.Name, rrType uint16) ([]byte, bool) {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil, false
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		// Non-zero RCODE indicates a forged or hijacked response.
		return nil, true
	}

	if len(resp.Answer) < 1 {
		return nil, false
	}

	// For A/AAAA, collect RDATA from all answer RRs.
	if rrType == dns.RRTypeA || rrType == dns.RRTypeAAAA {
		var chunks [][]byte
		for _, answer := range resp.Answer {
			if answer.Type != rrType {
				return nil, false
			}
			chunks = append(chunks, answer.Data)
		}
		var payload []byte
		var err error
		if rrType == dns.RRTypeA {
			payload, err = dns.DecodeRDataA(chunks)
		} else {
			payload, err = dns.DecodeRDataAAAA(chunks)
		}
		if err != nil {
			return nil, false
		}
		return payload, false
	}

	// All other types: single answer RR.
	if len(resp.Answer) != 1 {
		return nil, false
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		return nil, false
	}

	if answer.Type != rrType {
		return nil, false
	}

	var payload []byte
	var err error
	switch rrType {
	case dns.RRTypeNULL:
		payload, err = dns.DecodeRDataNULL(answer.Data)
	case dns.RRTypeHINFO:
		payload, err = dns.DecodeRDataHINFO(answer.Data)
	case dns.RRTypeCAA:
		payload, err = dns.DecodeRDataCAA(answer.Data)
	case dns.RRTypeCERT:
		payload, err = dns.DecodeRDataCERT(answer.Data)
	case dns.RRTypeCNAME:
		payload, err = dns.DecodeRDataCNAME(answer.Data, domain)
	case dns.RRTypeNS:
		payload, err = dns.DecodeRDataNS(answer.Data, domain)
	case dns.RRTypeMX:
		payload, err = dns.DecodeRDataMX(answer.Data, domain)
	case dns.RRTypeSRV:
		payload, err = dns.DecodeRDataSRV(answer.Data, domain)
	case dns.RRTypeHTTPS:
		payload, err = dns.DecodeRDataHTTPS(answer.Data, domain)
	default:
		payload, err = dns.DecodeRDataTXT(answer.Data)
	}
	if err != nil {
		return nil, false
	}

	return payload, false
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		// We may return a real io.EOF only here.
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	// Here we must change io.EOF to io.ErrUnexpectedEOF.
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Warnf("transient read error on DNS socket: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Warnf("dropped malformed DNS response: %v", err)
			continue
		}

		payload, isForged := dnsResponsePayload(&resp, c.domain, c.rrType)
		if isForged {
			// The resolver is reachable even if it returns an error response.
			// Treat that as transport success so stale detection does not
			// churn sessions in shared-socket mode.
			c.markSuccess()
			c.forgedStats.Record(resp.Flags & 0x000f)
			continue
		}

		// Mark success on receiving valid response (pulled out packets for processing)
		c.markSuccess()

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}

		// If the payload contained one or more packets, permit sendLoop
		// to poll immediately.
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr).
//
// VayDNS encoding format:
//   - Data query:  [ClientID:N][DataLen:1][Data]
//   - Poll query:  [ClientID:N][0][Nonce:4]  (0 marker + 4 random bytes)
//
// The encoded bytes are base32-encoded, split into 63-byte labels, and
// appended with the tunnel domain to form the DNS query name. Label count
// and total QNAME length are constrained by maxQnameLen and maxNumLabels.
	// The query QTYPE is set to rrType to match the server's configured
	// response encoding.
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	const labelLen = 63 // DNS maximum label size

	domain := c.domain

	// Calculate domain wire length (each label: 1 length byte + content).
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Calculate available wire bytes for data labels.
	maxQnameLen := c.maxQnameLen
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return fmt.Errorf("domain %s is too long for max-qname-len %d", domain.String(), c.maxQnameLen)
	}

	// Calculate encoded capacity from wire bytes.
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	// If maxNumLabels is limited, also cap the encoded capacity.
	if c.maxNumLabels > 0 {
		maxEncoded := c.maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	buf.Write(c.clientID.Bytes())
	if len(p) > 0 {
		if len(p) > c.wireConfig.MaxDataLen() {
			return fmt.Errorf("too long")
		}
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	} else {
		buf.WriteByte(pollMarker)
		io.CopyN(buf, rand.Reader, pollNonceLen)
	}
	decoded := buf.Bytes()

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)

	// Truncate encoded data to fit within constraints.
	if len(encoded) > encodedCapacity {
		encoded = encoded[:encodedCapacity]
	}
	labels := chunks(encoded, labelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  c.rrType,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	bufWire, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(bufWire, addr)
	return err
}

// sendWorker is a background worker that dequeues packets from workChan,
// and sends them on the network.
func (c *DNSPacketConn) sendWorker(transport net.PacketConn, addr net.Addr, workChan <-chan []byte) {
	closed := c.QueuePacketConn.Closed()
	for {
		select {
		case <-closed:
			return
		case p, ok := <-workChan:
			if !ok {
				return
			}
			err := c.send(transport, p, addr)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					log.Warnf("DNS query timed out: %v", err)
					continue
				}
				log.Debugf("DNS send error: %v", err)
			}
		}
	}
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr, numWorkers int) error {
	// For shared socket mode, a large number of workers is counter-productive
	// as it causes packet reordering and RTT distortion when combined with
	// rate limiting.
	if numWorkers > 8 {
		numWorkers = 8
	}
	workChan := make(chan []byte)
	defer close(workChan)
	for i := 0; i < numWorkers; i++ {
		go c.sendWorker(transport, addr, workChan)
	}

	pollDelay := c.currentPollDelay()
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	outgoing := c.QueuePacketConn.OutgoingQueue(addr)
	closed := c.QueuePacketConn.Closed()
	for {
		var p []byte
		pollTimerExpired := false
		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		select {
		case <-closed:
			return nil
		case p = <-outgoing:
		default:
			select {
			case <-closed:
				return nil
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// A data-carrying packet displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			currentMaxPollDelay := c.currentPollMaxDelay()
			if pollDelay > currentMaxPollDelay {
				pollDelay = currentMaxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = c.currentPollDelay()
		}
		pollTimer.Reset(pollDelay)

		// Wait for rate limit token BEFORE pulling the next packet or
		// dispatching a poll. This ensures KCP's RTT calculation is
		// accurate and workers don't hold packets in-memory during sleep.
		c.rateLimiter.Wait()

		// Dispatch the packet (data or nil poll) to a worker.
		select {
		case <-closed:
			return nil
		case workChan <- p:
		}
	}
}
