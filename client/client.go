// Package client provides a reusable DNS tunnel client library.
//
// It provides configuration options for VayDNS features (per-query UDP,
// forged response filtering, rate limiting, etc.).
//
// Basic usage (xray-core compatible):
//
//	r, _ := client.NewResolver("8.8.8.8:53")
//	ts, _ := client.NewTunnelServer("t.example.com")
//	t, _ := client.NewTunnel(r, ts)
//	t.InitiateResolverConnection()
//	t.InitiateDNSPacketConn(ts.Addr)
//	t.InitiateKCPConn(ts.MTU)
//	t.InitiateSmuxSession()
//	stream, _ := t.OpenStream() // returns net.Conn
//	defer t.Close()
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
	log "github.com/sirupsen/logrus"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Default timeouts for VayDNS mode.
const (
	DefaultIdleTimeout              = 10 * time.Second
	DefaultKeepAlive                = 2 * time.Second
	DefaultOpenStreamTimeout        = 10 * time.Second
	DefaultReconnectDelay           = 1 * time.Second
	DefaultReconnectMaxDelay        = 30 * time.Second
	DefaultSessionCheckInterval     = 500 * time.Millisecond
	DefaultUDPResponseTimeout       = 500 * time.Millisecond
	DefaultUDPWorkers               = 100
	DefaultMaxStreams               = 0 // unlimited
	DefaultPollDelay                = 500 * time.Millisecond
	DefaultActivePollDelay          = 200 * time.Millisecond
	DefaultPollMaxDelay             = 2 * time.Second
	DefaultUDPTransportStaleTimeout = 10 * time.Second
	DefaultOpenStreamFailureLimit   = 10
)

// Resolver holds DNS resolver configuration.
type Resolver struct {
	ResolverAddr string // UDP resolver address, for example "8.8.8.8:53".

	// DialerControl is an optional callback for setting socket options
	// (SO_MARK, SO_BINDTODEVICE, etc.) on UDP sockets.
	DialerControl func(network, address string, c syscall.RawConn) error

	// UDP transport settings.
	UDPWorkers      int           // concurrent UDP workers (0 = DefaultUDPWorkers)
	UDPSharedSocket bool          // use single shared socket instead of per-query
	UDPTimeout      time.Duration // per-query response timeout (0 = DefaultUDPResponseTimeout)
	UDPAcceptErrors bool          // pass through non-NOERROR responses (default: filter)
}

// NewResolver creates a Resolver for the given UDP resolver address.
func NewResolver(resolverAddr string) (Resolver, error) {
	return Resolver{ResolverAddr: resolverAddr}, nil
}

// TunnelServer holds tunnel server configuration.
type TunnelServer struct {
	Addr dns.Name
	MTU  int // auto-computed if 0 when InitiateKCPConn is called

	// ClientIDSize is the ClientID size in bytes (default: 2).
	ClientIDSize int

	// MaxQnameLen is the maximum QNAME wire length (default: 101).
	MaxQnameLen int

	// MaxNumLabels is the maximum number of data labels (default: 0 = unlimited).
	MaxNumLabels int

	// RPS limits outgoing DNS queries per second (default: 0 = unlimited).
	RPS float64

	// RecordType selects the DNS record type for downstream data.
	// Supported values: "txt" (default), "cname", "a", "aaaa", "mx", "ns", "srv".
	RecordType string
}

// NewTunnelServer creates a TunnelServer from a domain string.
func NewTunnelServer(addr string) (TunnelServer, error) {
	domain, err := dns.ParseName(addr)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("invalid domain %+q: %w", addr, err)
	}

	return TunnelServer{
		Addr: domain,
	}, nil
}

// wireConfig returns the WireConfig derived from the TunnelServer settings.
func (ts *TunnelServer) wireConfig() turbotunnel.WireConfig {
	size := ts.ClientIDSize
	if size <= 0 {
		size = 2
	}
	return turbotunnel.WireConfig{ClientIDSize: size}
}

// effectiveRRType returns the DNS RR type for downstream data.
func (ts *TunnelServer) effectiveRRType() uint16 {
	rt, err := dns.ParseRecordType(ts.RecordType)
	if err != nil {
		return dns.RRTypeTXT
	}
	return rt
}

// effectiveMaxQnameLen returns the configured max QNAME length.
func (ts *TunnelServer) effectiveMaxQnameLen() int {
	if ts.MaxQnameLen > 0 {
		return ts.MaxQnameLen
	}
	return 101
}

// Tunnel represents a DNS tunnel connection. Create with NewTunnel, then
// either call the step-by-step Initiate* methods (for embedding in frameworks
// like xray-core) or call ListenAndServe for a fully managed session.
type Tunnel struct {
	Resolver     Resolver
	TunnelServer TunnelServer

	// Session configuration. Zero values use defaults.
	IdleTimeout              time.Duration                 // default: 10s
	KeepAlive                time.Duration                 // default: 2s
	OpenStreamTimeout        time.Duration                 // default: 10s
	MaxStreams               int                           // default: 0 (0 = unlimited)
	ReconnectMinDelay        time.Duration                 // default: 1s
	ReconnectMaxDelay        time.Duration                 // default: 30s
	SessionCheckInterval     time.Duration                 // default: 500ms
	PacketQueueSize          int                           // default: QueueSize (512)
	KCPWindowSize            int                           // default: PacketQueueSize/2
	QueueOverflowMode        turbotunnel.QueueOverflowMode // default: drop
	PollDelay                time.Duration                 // default: 500ms
	ActivePollDelay          time.Duration                 // default: 200ms
	PollMaxDelay             time.Duration                 // default: 2s
	UDPTransportStaleTimeout time.Duration                 // default: 10s (UDP per-query only)
	OpenStreamFailureLimit   int                           // default: 10 consecutive idle failures

	// internal state
	wireConfig    turbotunnel.WireConfig
	forgedStats   *ForgedStats
	resolverConn  net.PacketConn
	dnsPacketConn *DNSPacketConn
	kcpConn       *kcp.UDPSession
	smuxSession   *smux.Session
	remoteAddr    net.Addr
	activeStreams atomic.Int32
}

// NewTunnel creates a Tunnel with the given resolver and server configuration.
// Zero-value fields use sensible defaults.
func NewTunnel(resolver Resolver, tunnelServer TunnelServer) (*Tunnel, error) {
	t := &Tunnel{
		Resolver:     resolver,
		TunnelServer: tunnelServer,
	}
	t.wireConfig = tunnelServer.wireConfig()
	return t, nil
}

func (t *Tunnel) applyDefaults() {
	if t.IdleTimeout == 0 {
		t.IdleTimeout = DefaultIdleTimeout
	}
	if t.KeepAlive == 0 {
		t.KeepAlive = DefaultKeepAlive
	}
	if t.OpenStreamTimeout == 0 {
		t.OpenStreamTimeout = DefaultOpenStreamTimeout
	}
	if t.MaxStreams == 0 {
		t.MaxStreams = DefaultMaxStreams
	}
	if t.ReconnectMinDelay == 0 {
		t.ReconnectMinDelay = DefaultReconnectDelay
	}
	if t.ReconnectMaxDelay == 0 {
		t.ReconnectMaxDelay = DefaultReconnectMaxDelay
	}
	if t.SessionCheckInterval == 0 {
		t.SessionCheckInterval = DefaultSessionCheckInterval
	}
	if t.PollDelay == 0 {
		t.PollDelay = DefaultPollDelay
	}
	if t.ActivePollDelay == 0 {
		t.ActivePollDelay = DefaultActivePollDelay
	}
	if t.PollMaxDelay == 0 {
		t.PollMaxDelay = DefaultPollMaxDelay
	}
	if t.UDPTransportStaleTimeout == 0 {
		t.UDPTransportStaleTimeout = DefaultUDPTransportStaleTimeout
	}
	if t.OpenStreamFailureLimit == 0 {
		t.OpenStreamFailureLimit = DefaultOpenStreamFailureLimit
	}
}

func (t *Tunnel) effectivePacketQueueSize() int {
	if t.PacketQueueSize > 0 {
		return t.PacketQueueSize
	}
	return turbotunnel.QueueSize
}

func (t *Tunnel) effectiveQueueOverflowMode() turbotunnel.QueueOverflowMode {
	if t.QueueOverflowMode != "" {
		return t.QueueOverflowMode
	}
	return turbotunnel.DefaultQueueOverflowMode
}

func (t *Tunnel) effectiveKCPWindowSize() int {
	if t.KCPWindowSize > 0 {
		return t.KCPWindowSize
	}
	ws := t.effectivePacketQueueSize() / 2
	if ws < 1 {
		ws = 1
	}
	return ws
}

// InitiateResolverConnection creates the underlying transport connection
// based on the Resolver configuration.
func (t *Tunnel) InitiateResolverConnection() error {
	r := t.Resolver
	addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
	if err != nil {
		return err
	}
	t.remoteAddr = addr
	if r.UDPSharedSocket {
		lc := net.ListenConfig{Control: r.DialerControl}
		conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			return err
		}
		t.resolverConn = conn
	} else {
		workers := r.UDPWorkers
		if workers <= 0 {
			workers = DefaultUDPWorkers
		}
		timeout := r.UDPTimeout
		if timeout <= 0 {
			timeout = DefaultUDPResponseTimeout
		}
		conn, forgedStats, err := NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors, t.effectivePacketQueueSize(), t.effectiveQueueOverflowMode())
		if err != nil {
			return err
		}
		t.forgedStats = forgedStats
		t.resolverConn = conn
	}
	return nil
}

// InitiateDNSPacketConn wraps the resolver connection with DNS encoding.
func (t *Tunnel) InitiateDNSPacketConn(domain dns.Name) error {
	t.applyDefaults()
	var rateLimiter *RateLimiter
	if t.TunnelServer.RPS > 0 {
		rateLimiter = NewRateLimiter(t.TunnelServer.RPS)
	}
	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	rrType := t.TunnelServer.effectiveRRType()
	t.dnsPacketConn = newDNSPacketConn(
		t.resolverConn,
		t.remoteAddr,
		domain,
		rateLimiter,
		maxQnameLen,
		t.TunnelServer.MaxNumLabels,
		t.wireConfig,
		t.forgedStats,
		rrType,
		&t.activeStreams,
		t.PollDelay,
		t.ActivePollDelay,
		t.PollMaxDelay,
		t.effectivePacketQueueSize(),
		t.effectiveQueueOverflowMode(),
	)
	return nil
}

// InitiateKCPConn opens a KCP connection over the DNS packet connection.
// If mtu is 0, it is auto-computed from the domain and QNAME constraints.
func (t *Tunnel) InitiateKCPConn(mtu int) error {
	if mtu <= 0 {
		maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
		mtu = DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	}
	if mtu < 25 {
		return fmt.Errorf("MTU %d is too small (minimum 25); try increasing -max-qname-len (currently %d), increasing -max-num-labels (currently %d), using a shorter domain, or decreasing -clientid-size (currently %d)",
			mtu, t.TunnelServer.effectiveMaxQnameLen(), t.TunnelServer.MaxNumLabels, t.wireConfig.ClientIDSize)
	}
	t.TunnelServer.MTU = mtu
	log.Infof("effective MTU %d", mtu)

	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	log.Infof("session %08x ready", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(t.effectiveKCPWindowSize(), t.effectiveKCPWindowSize())
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	t.kcpConn = conn
	return nil
}

// InitiateSmuxSession establishes a multiplexed session over KCP.
func (t *Tunnel) InitiateSmuxSession() error {
	t.applyDefaults()
	if t.kcpConn == nil {
		return fmt.Errorf("KCP session is not initialized")
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(t.kcpConn, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	t.smuxSession = sess
	return nil
}

// openStreamWithTimeout opens an smux stream with a timeout. If the open
// succeeds after the timeout, the late stream is closed to avoid leaking
// capacity.
func openStreamWithTimeout(conv uint32, timeout time.Duration, open func() (*smux.Stream, error)) (*smux.Stream, error) {
	type result struct {
		stream *smux.Stream
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := open()
		ch <- result{s, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("session %08x opening stream: %w", conv, r.err)
		}
		return r.stream, nil
	case <-timer.C:
		go func() {
			if r, ok := <-ch; ok && r.stream != nil {
				r.stream.Close()
			}
		}()
		return nil, fmt.Errorf("session %08x opening stream: timed out after %v", conv, timeout)
	}
}

// shouldLogCopyError returns true if the error from io.Copy is worth logging.
// Expected close/EOF/timeout errors are filtered out.
func shouldLogCopyError(err error) bool {
	if err == nil || err == io.EOF || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

// OpenStream opens a new multiplexed stream. Returns a net.Conn.
func (t *Tunnel) OpenStream() (net.Conn, error) {
	if t.smuxSession == nil {
		return nil, fmt.Errorf("smux session is not initialized")
	}

	timeout := t.OpenStreamTimeout
	if timeout <= 0 {
		timeout = DefaultOpenStreamTimeout
	}

	var conv uint32
	if t.kcpConn != nil {
		conv = t.kcpConn.GetConv()
	}

	stream, err := openStreamWithTimeout(conv, timeout, t.smuxSession.OpenStream)
	if err != nil {
		if errors.Is(err, smux.ErrGoAway) && t.smuxSession != nil && !t.smuxSession.IsClosed() {
			log.Warnf("session %08x stream IDs exhausted; closing smux session for rollover", conv)
			t.smuxSession.Close()
		}
		return nil, err
	}
	log.Debugf("stream %08x:%d ready", conv, stream.ID())
	return stream, nil
}

// Handle forwards data between a local TCP connection and a tunnel stream.
func (t *Tunnel) Handle(lconn *net.TCPConn) error {
	if err := lconn.SetNoDelay(true); err != nil {
		log.Debugf("local TCP_NODELAY: %v", err)
	}
	t.activeStreams.Add(1)
	defer t.activeStreams.Add(-1)

	stream, err := t.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, lconn)
		if shouldLogCopyError(err) {
			log.Warnf("copy stream←local: %v", err)
		}
		lconn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(lconn, stream)
		if shouldLogCopyError(err) {
			log.Warnf("copy local←stream: %v", err)
		}
		lconn.CloseWrite()
		lconn.CloseRead()
	}()
	wg.Wait()

	return nil
}

// Close tears down the tunnel and all its layers.
func (t *Tunnel) Close() error {
	if t.smuxSession != nil {
		t.smuxSession.Close()
		t.smuxSession = nil
	}
	if t.kcpConn != nil {
		log.Debugf("session %08x closed", t.kcpConn.GetConv())
		t.kcpConn.Close()
		t.kcpConn = nil
	}
	t.closeTransportLayers()
	return nil
}

// closeTransportLayers tears down the DNS and resolver transport layers.
// Safe to call multiple times.
func (t *Tunnel) closeTransportLayers() {
	if t.dnsPacketConn != nil {
		t.dnsPacketConn.Close()
		t.dnsPacketConn = nil
	}
	if t.resolverConn != nil {
		t.resolverConn.Close()
		t.resolverConn = nil
	}
	t.forgedStats = nil
}

// resetTransportLayers tears down existing transport layers and creates fresh
// ones. Used during reconnect to ensure a clean transport stack.
func (t *Tunnel) resetTransportLayers() error {
	t.closeTransportLayers()
	if err := t.InitiateResolverConnection(); err != nil {
		return fmt.Errorf("resolver connection: %w", err)
	}
	if err := t.InitiateDNSPacketConn(t.TunnelServer.Addr); err != nil {
		t.closeTransportLayers()
		return fmt.Errorf("DNS packet conn: %w", err)
	}
	return nil
}

func (t *Tunnel) udpTransportStaleAge(requireTraffic bool) time.Duration {
	if !requireTraffic || t.UDPTransportStaleTimeout <= 0 {
		return 0
	}
	if t.Resolver.UDPSharedSocket {
		return 0
	}
	udpConn, ok := t.resolverConn.(*UDPPacketConn)
	if !ok {
		return 0
	}
	lastSuccess := udpConn.lastSuccessTime()
	if lastSuccess.IsZero() {
		return 0
	}
	return time.Since(lastSuccess)
}

// ListenAndServe starts a TCP listener and forwards connections through the
// tunnel with automatic session reconnection. This is the main entry point
// for the CLI.
func (t *Tunnel) ListenAndServe(listenAddr string) error {
	t.applyDefaults()

	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %v", err)
	}

	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	mtu := DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	if mtu < 25 {
		return fmt.Errorf("MTU %d is too small (minimum 25); try increasing -max-qname-len (currently %d), increasing -max-num-labels (currently %d), using a shorter domain, or decreasing -clientid-size (currently %d)",
			mtu, maxQnameLen, t.TunnelServer.MaxNumLabels, t.wireConfig.ClientIDSize)
	}
	log.Infof("effective MTU %d", mtu)

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()
	defer t.closeTransportLayers()

	var sem chan struct{}
	if t.MaxStreams > 0 {
		sem = make(chan struct{}, t.MaxStreams)
	}

	for {
		// Rebuild the transport stack from the resolver upward.
		var transportErrCh <-chan error
		delay := t.ReconnectMinDelay
		for {
			if err := t.resetTransportLayers(); err != nil {
				log.Warnf("transport rebuild failed: %v; retrying in %v", err, delay)
				time.Sleep(delay)
				delay *= 2
				if delay > t.ReconnectMaxDelay {
					delay = t.ReconnectMaxDelay
				}
				continue
			}
			transportErrCh = t.dnsPacketConn.TransportErrors()
			break
		}

		// Create a new tunnel session with exponential backoff.
		var conn *kcp.UDPSession
		var sess *smux.Session
		delay = t.ReconnectMinDelay
		for {
			conn, sess, err = t.createSession(mtu)
			if err == nil {
				log.Infof("session %08x ready", conn.GetConv())
				break
			}
			log.Warnf("session creation failed: %v; rebuilding transport and retrying in %v", err, delay)
			t.closeTransportLayers()
			for {
				if err := t.resetTransportLayers(); err != nil {
					log.Warnf("transport rebuild failed: %v; retrying in %v", err, delay)
					time.Sleep(delay)
					delay *= 2
					if delay > t.ReconnectMaxDelay {
						delay = t.ReconnectMaxDelay
					}
					continue
				}
				transportErrCh = t.dnsPacketConn.TransportErrors()
				break
			}
			time.Sleep(delay)
			delay *= 2
			if delay > t.ReconnectMaxDelay {
				delay = t.ReconnectMaxDelay
			}
		}

		sessDone := sess.CloseChan()
		conv := conn.GetConv()
		var openFailCount atomic.Int32

		sessionAlive := true
		for sessionAlive {
			ln.SetDeadline(time.Now().Add(t.SessionCheckInterval))
			local, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if age := t.udpTransportStaleAge(t.activeStreams.Load() > 0); age > t.UDPTransportStaleTimeout {
						log.Warnf("session %08x transport stale after %s with %d active streams", conv, age.Round(time.Second), t.activeStreams.Load())
						sessionAlive = false
						continue
					}
					select {
					case <-sessDone:
						sessionAlive = false
					case tErr := <-transportErrCh:
						log.Warnf("session %08x transport error: %v", conv, tErr)
						sessionAlive = false
					default:
					}
					continue
				}
				sess.Close()
				conn.Close()
				t.closeTransportLayers()
				return err
			}

			select {
			case <-sessDone:
				local.Close()
				sessionAlive = false
				continue
			case tErr := <-transportErrCh:
				log.Warnf("session %08x transport error: %v", conv, tErr)
				local.Close()
				sessionAlive = false
				continue
			default:
			}
			if age := t.udpTransportStaleAge(t.activeStreams.Load() > 0 || openFailCount.Load() > 0); age > t.UDPTransportStaleTimeout {
				log.Warnf("session %08x transport stale after %s while streams need transport", conv, age.Round(time.Second))
				local.Close()
				sessionAlive = false
				continue
			}

			go func(local *net.TCPConn, sess *smux.Session, conv uint32, openFailCount *atomic.Int32) {
				if sem != nil {
					sem <- struct{}{}
					defer func() { <-sem }()
				}
				defer local.Close()
				err := t.handleConn(local, sess, conv, openFailCount)
				if err != nil {
					log.Warnf("handle: %v", err)
					if t.activeStreams.Load() == 0 {
						failures := openFailCount.Add(1)
						if failures >= int32(t.OpenStreamFailureLimit) && !sess.IsClosed() {
							log.Warnf("session %08x retiring idle session after %d consecutive stream-open failures", conv, failures)
							sess.Close()
						}
					}
				}
			}(local.(*net.TCPConn), sess, conv, &openFailCount)
		}

		log.Warnf("session %08x closed, reconnecting", conv)
		sess.Close()
		conn.Close()
		t.closeTransportLayers()
	}
}

// createSession creates a KCP+smux session (used by ListenAndServe).
func (t *Tunnel) createSession(mtu int) (*kcp.UDPSession, *smux.Session, error) {
	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil {
		return nil, nil, fmt.Errorf("opening KCP conn: %v", err)
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(t.effectiveKCPWindowSize(), t.effectiveKCPWindowSize())
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("opening smux session: %v", err)
	}

	return conn, sess, nil
}

// handleConn forwards a single TCP connection through the tunnel session.
func (t *Tunnel) handleConn(local *net.TCPConn, sess *smux.Session, conv uint32, openFailCount *atomic.Int32) error {
	if err := local.SetNoDelay(true); err != nil {
		log.Debugf("stream %08x local TCP_NODELAY: %v", conv, err)
	}
	t.activeStreams.Add(1)
	defer t.activeStreams.Add(-1)

	stream, err := openStreamWithTimeout(conv, t.OpenStreamTimeout, sess.OpenStream)
	if err != nil {
		if errors.Is(err, smux.ErrGoAway) && !sess.IsClosed() {
			log.Warnf("session %08x stream IDs exhausted; closing smux session for rollover", conv)
			sess.Close()
		}
		return err
	}
	if openFailCount != nil {
		openFailCount.Store(0)
	}

	defer func() {
		log.Debugf("stream %08x:%d closed", conv, stream.ID())
		stream.Close()
	}()
	log.Infof("stream %08x:%d ready", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if shouldLogCopyError(err) {
			log.Warnf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if shouldLogCopyError(err) {
			log.Warnf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
		local.CloseRead()
	}()
	wg.Wait()

	return nil
}

// DNSNameCapacity returns the number of raw bytes that can be encoded in a DNS
// query name, given the domain suffix and encoding constraints.
func DNSNameCapacity(domain dns.Name, maxQnameLen int, maxNumLabels int) int {
	const labelLen = 63

	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}

	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return 0
	}

	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	if maxNumLabels > 0 {
		maxEncoded := maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	rawCapacity := encodedCapacity * 5 / 8
	return rawCapacity
}

// Outbound provides a high-level API for creating tunnels from multiple
// resolvers and tunnel servers.
type Outbound struct {
	Resolvers     []Resolver
	TunnelServers []TunnelServer
	tunnels       []*Tunnel
}

// NewOutbound creates an Outbound with the given resolvers and tunnel servers.
func NewOutbound(resolvers []Resolver, tunnelServers []TunnelServer) *Outbound {
	return &Outbound{
		Resolvers:     resolvers,
		TunnelServers: tunnelServers,
	}
}

// Start begins accepting connections on bind and forwarding them through the
// first resolver/server pair.
func (o *Outbound) Start(bind string) error {
	resolver := o.Resolvers[0]
	tunnelServer := o.TunnelServers[0]

	tunnel, err := NewTunnel(resolver, tunnelServer)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}
	o.tunnels = []*Tunnel{tunnel}

	return tunnel.ListenAndServe(bind)
}
