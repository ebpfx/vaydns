package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

// TCPPacketConn implements net.PacketConn using per-query TCP connections. Each
// outgoing DNS query is sent on a fresh TCP connection, which gives the client
// multiple concurrent source ports instead of a single long-lived 4-tuple.
//
// A pool of worker goroutines dequeues packets from the embedded
// QueuePacketConn, dials the resolver, sends one length-prefixed DNS message,
// and reads responses back into the incoming queue. When ignoreErrors is true
// (default), workers skip non-NOERROR responses and keep reading until a valid
// response arrives or the per-query timeout expires.
type TCPPacketConn struct {
	resolverAddr    string
	dialerControl   func(network, address string, c syscall.RawConn) error
	responseTimeout time.Duration
	ignoreErrors    bool
	forgedStats     *ForgedStats
	*turbotunnel.QueuePacketConn
}

// NewTCPPacketConn creates a TCPPacketConn with numWorkers goroutines that
// each send one query at a time on a fresh TCP connection. The returned
// ForgedStats pointer is shared with the caller so DNSPacketConn can include
// per-query forged counts in its reporting.
func NewTCPPacketConn(resolverAddr string, dialerControl func(network, address string, c syscall.RawConn) error, numWorkers int, responseTimeout time.Duration, ignoreErrors bool, queueSize int, overflowMode turbotunnel.QueueOverflowMode) (*TCPPacketConn, *ForgedStats, error) {
	stats := &ForgedStats{}
	pconn := &TCPPacketConn{
		resolverAddr:    resolverAddr,
		dialerControl:   dialerControl,
		responseTimeout: responseTimeout,
		ignoreErrors:    ignoreErrors,
		forgedStats:     stats,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0, queueSize, overflowMode),
	}
	for i := 0; i < numWorkers; i++ {
		go pconn.sendLoop()
	}
	return pconn, stats, nil
}

// sendLoop is the per-worker loop. It dequeues one packet at a time from the
// outgoing queue, sends it on a fresh TCP connection, reads the response, and
// queues valid responses for the upper layer. On consecutive dial/send/recv
// failures, it backs off exponentially to avoid CPU spinning when the
// resolver is unreachable.
func (c *TCPPacketConn) sendLoop() {
	const (
		initBackoff = 100 * time.Millisecond
		maxBackoff  = 5 * time.Second
	)
	backoff := initBackoff
	queueAddr := turbotunnel.DummyAddr{}
	outgoing := c.OutgoingQueue(queueAddr)
	closed := c.Closed()

	for {
		var p []byte
		select {
		case <-closed:
			return
		case p = <-outgoing:
		}
		if err := c.sendRecv(p); err != nil {
			timer := time.NewTimer(backoff)
			select {
			case <-closed:
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = initBackoff
		}
	}
}

// sendRecv sends a single DNS query on a fresh TCP connection and reads the
// response. If ignoreErrors is set, it keeps reading past non-NOERROR
// responses until a valid one arrives or the timeout expires. Returns nil on
// success, or an error if the query could not be sent or no valid response
// arrived within the timeout.
func (c *TCPPacketConn) sendRecv(p []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.responseTimeout)
	defer cancel()

	dialer := &net.Dialer{Control: c.dialerControl}
	conn, err := dialer.DialContext(ctx, "tcp", c.resolverAddr)
	if err != nil {
		log.Warnf("tcp worker: DialContext: %v", err)
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			log.Warnf("tcp worker: SetDeadline: %v", err)
			return err
		}
	}

	bw := bufio.NewWriter(conn)
	length := uint16(len(p))
	if int(length) != len(p) {
		panic(len(p))
	}
	if err := binary.Write(bw, binary.BigEndian, &length); err != nil {
		log.Warnf("tcp worker: binary.Write: %v", err)
		return err
	}
	if _, err := bw.Write(p); err != nil {
		log.Warnf("tcp worker: Write: %v", err)
		return err
	}
	if err := bw.Flush(); err != nil {
		log.Warnf("tcp worker: Flush: %v", err)
		return err
	}

	br := bufio.NewReader(conn)
	for {
		var length uint16
		if err := binary.Read(br, binary.BigEndian, &length); err != nil {
			return err
		}

		respBuf := make([]byte, int(length))
		if _, err := io.ReadFull(br, respBuf); err != nil {
			return err
		}

		resp, err := dns.MessageFromWireFormat(respBuf)
		if err != nil {
			log.Debugf("tcp worker: MessageFromWireFormat: %v", err)
			continue
		}

		if resp.Flags&0x000f != dns.RcodeNoError {
			rcode := resp.Flags & 0x000f
			if c.ignoreErrors {
				c.forgedStats.Record(rcode)
				continue
			}
			log.Debugf("tcp worker: passing through error response (rcode=%d)", rcode)
		}

		c.QueueIncoming(respBuf, turbotunnel.DummyAddr{})
		return nil
	}
}
