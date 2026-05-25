// vaydns-client is the client end of a DNS tunnel.
//
// Usage:
//
//	vaydns-client -udp ADDR -domain DOMAIN -listen LOCALADDR
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/net2share/vaydns/client"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
	"github.com/net2share/vaydns/udpaddr"
	log "github.com/sirupsen/logrus"
)

var version = "dev"

func main() {
	var showVersion bool
	var domainArg string
	var listenAddr string
	var udpAddr string
	var maxQnameLen int
	var maxNumLabels int
	var rpsLimit float64
	var idleTimeoutStr string
	var keepAliveStr string
	var reconnectMinStr string
	var reconnectMaxStr string
	var openStreamTimeoutStr string
	var pollDelayStr string
	var activePollDelayStr string
	var pollMaxDelayStr string
	var udpTransportStaleTimeoutStr string
	var openStreamFailureLimit int
	var udpWorkers int
	var udpPerQuerySockets bool
	var udpTimeoutStr string
	var udpAcceptErrors bool
	var clientIDSize int
	var recordTypeStr string
	var queueSize int
	var kcpWindowSize int
	var queueOverflowStr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -udp ADDR -domain DOMAIN -listen LOCALADDR

Examples:
  %[1]s -udp 8.8.8.8:53 -domain t.example.com -listen 127.0.0.1:7000

`, os.Args[0])
		flag.CommandLine.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(flag.CommandLine.Output(), "  -%s", f.Name)
			name, usage := flag.UnquoteUsage(f)
			if len(name) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), " %s", name)
			}
			if len(f.DefValue) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), " (default %s)", f.DefValue)
			}
			if len(usage) > 0 {
				fmt.Fprintf(flag.CommandLine.Output(), "\n    \t%s", usage)
			}
			fmt.Fprint(flag.CommandLine.Output(), "\n")
		})
	}
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&domainArg, "domain", "", "tunnel domain (e.g., t.example.com)")
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:10888", "TCP address to listen on for local connections (default 127.0.0.1:10888)")
	flag.IntVar(&maxQnameLen, "max-qname-len", 63, "maximum total QNAME length in wire format (0 = 253 per RFC 1035)")
	flag.IntVar(&maxNumLabels, "max-num-labels", 1, "maximum number of data labels in query name (0 = unlimited)")
	flag.Float64Var(&rpsLimit, "rps", 0, "limit outgoing DNS queries per second (0 = unlimited)")
	flag.StringVar(&idleTimeoutStr, "idle-timeout", client.DefaultIdleTimeout.String(), "session idle timeout (e.g. 10s, 30s); reconnects if no data received within this period")
	flag.StringVar(&keepAliveStr, "keepalive", client.DefaultKeepAlive.String(), "keepalive ping interval (e.g. 2s, 1s); must be less than idle-timeout")
	flag.StringVar(&reconnectMinStr, "reconnect-min", client.DefaultReconnectDelay.String(), "minimum delay before retrying session creation (e.g. 500ms, 1s)")
	flag.StringVar(&reconnectMaxStr, "reconnect-max", client.DefaultReconnectMaxDelay.String(), "maximum delay before retrying session creation (e.g. 5s, 30s)")
	flag.StringVar(&openStreamTimeoutStr, "open-stream-timeout", client.DefaultOpenStreamTimeout.String(), "timeout for opening an smux stream (e.g. 500ms, 3s)")
	flag.StringVar(&pollDelayStr, "poll-delay", client.DefaultPollDelay.String(), "base delay before sending an empty DNS poll when idle (e.g. 500ms, 1s)")
	flag.StringVar(&activePollDelayStr, "active-poll-delay", client.DefaultActivePollDelay.String(), "poll delay cap while streams are active or being opened (e.g. 200ms, 500ms)")
	flag.StringVar(&pollMaxDelayStr, "poll-max-delay", client.DefaultPollMaxDelay.String(), "maximum idle backoff between empty DNS polls (e.g. 2s, 5s)")
	flag.StringVar(&udpTransportStaleTimeoutStr, "udp-transport-stale-timeout", client.DefaultUDPTransportStaleTimeout.String(), "retire the current session if per-query UDP sees no valid response for this long while streams need transport (e.g. 15s, 30s)")
	flag.IntVar(&openStreamFailureLimit, "open-stream-failure-limit", client.DefaultOpenStreamFailureLimit, "retire an idle session after this many consecutive stream-open failures (e.g. 3, 10)")
	flag.IntVar(&udpWorkers, "udp-workers", client.DefaultUDPWorkers, "number of concurrent UDP worker goroutines (used with -udp-per-query-sockets)")
	flag.BoolVar(&udpPerQuerySockets, "udp-per-query-sockets", false, "use per-query UDP sockets instead of the default shared socket")
	flag.StringVar(&udpTimeoutStr, "udp-timeout", client.DefaultUDPResponseTimeout.String(), "per-query UDP response timeout (e.g. 800ms, 1500ms)")
	flag.BoolVar(&udpAcceptErrors, "udp-accept-errors", false, "accept DNS error responses instead of filtering them (disables censorship evasion)")
	flag.IntVar(&clientIDSize, "clientid-size", 1, "client ID size in bytes")
	flag.StringVar(&recordTypeStr, "record-type", "null", "DNS record type for downstream data (txt, null, hinfo, cname, a, aaaa, mx, ns, srv, cert, https, caa)")
	flag.IntVar(&queueSize, "queue-size", turbotunnel.QueueSize, "packet queue size for transport and DNS layers")
	flag.IntVar(&kcpWindowSize, "kcp-window-size", 0, "KCP send/receive window size in packets (0 = queue-size/2)")
	flag.StringVar(&queueOverflowStr, "queue-overflow", string(turbotunnel.DefaultQueueOverflowMode), "queue overflow behavior: drop or block")

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

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments\n")
		flag.Usage()
		os.Exit(1)
	}
	if domainArg == "" {
		fmt.Fprintf(os.Stderr, "the -domain option is required\n")
		os.Exit(1)
	}

	if _, err := dns.ParseRecordType(recordTypeStr); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	recordTypeStr = strings.ToLower(recordTypeStr)

	if udpAddr == "" {
		fmt.Fprintf(os.Stderr, "the -udp option is required\n")
		os.Exit(1)
	}
	udpAddr, err = udpaddr.Normalize(udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp: %v\n", err)
		os.Exit(1)
	}

	// Parse durations.
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
	reconnectMinDelay, err := time.ParseDuration(reconnectMinStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-min: %v\n", err)
		os.Exit(1)
	}
	reconnectMaxDelay, err := time.ParseDuration(reconnectMaxStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-max: %v\n", err)
		os.Exit(1)
	}
	openStreamTimeout, err := time.ParseDuration(openStreamTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -open-stream-timeout: %v\n", err)
		os.Exit(1)
	}
	pollDelay, err := time.ParseDuration(pollDelayStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -poll-delay: %v\n", err)
		os.Exit(1)
	}
	activePollDelay, err := time.ParseDuration(activePollDelayStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -active-poll-delay: %v\n", err)
		os.Exit(1)
	}
	pollMaxDelay, err := time.ParseDuration(pollMaxDelayStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -poll-max-delay: %v\n", err)
		os.Exit(1)
	}
	udpTransportStaleTimeout, err := time.ParseDuration(udpTransportStaleTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp-transport-stale-timeout: %v\n", err)
		os.Exit(1)
	}
	udpTimeout, err := time.ParseDuration(udpTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp-timeout: %v\n", err)
		os.Exit(1)
	}

	// Validate.
	if keepAlive >= idleTimeout {
		fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
		os.Exit(1)
	}
	if reconnectMinDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-reconnect-min (%s) must be greater than 0\n", reconnectMinDelay)
		os.Exit(1)
	}
	if reconnectMaxDelay < reconnectMinDelay {
		fmt.Fprintf(os.Stderr, "-reconnect-max (%s) must be greater than or equal to -reconnect-min (%s)\n", reconnectMaxDelay, reconnectMinDelay)
		os.Exit(1)
	}
	if openStreamTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "-open-stream-timeout (%s) must be greater than 0\n", openStreamTimeout)
		os.Exit(1)
	}
	if pollDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-poll-delay (%s) must be greater than 0\n", pollDelay)
		os.Exit(1)
	}
	if activePollDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-active-poll-delay (%s) must be greater than 0\n", activePollDelay)
		os.Exit(1)
	}
	if pollMaxDelay < pollDelay {
		fmt.Fprintf(os.Stderr, "-poll-max-delay (%s) must be greater than or equal to -poll-delay (%s)\n", pollMaxDelay, pollDelay)
		os.Exit(1)
	}
	if udpTransportStaleTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "-udp-transport-stale-timeout (%s) must be greater than 0\n", udpTransportStaleTimeout)
		os.Exit(1)
	}
	if openStreamFailureLimit <= 0 {
		fmt.Fprintf(os.Stderr, "-open-stream-failure-limit (%d) must be greater than 0\n", openStreamFailureLimit)
		os.Exit(1)
	}
	if queueSize <= 0 {
		fmt.Fprintf(os.Stderr, "-queue-size (%d) must be greater than 0\n", queueSize)
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
	queueOverflowMode, err := turbotunnel.ParseQueueOverflowMode(queueOverflowStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -queue-overflow: %v\n", err)
		os.Exit(1)
	}

	if clientIDSize <= 0 {
		fmt.Fprintf(os.Stderr, "-clientid-size must be positive\n")
		os.Exit(1)
	}

	// Build resolver.
	resolver, err := client.NewResolver(udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolver: %v\n", err)
		os.Exit(1)
	}
	resolver.UDPWorkers = udpWorkers
	resolver.UDPSharedSocket = !udpPerQuerySockets
	resolver.UDPTimeout = udpTimeout
	resolver.UDPAcceptErrors = udpAcceptErrors
	if udpAcceptErrors {
		if !udpPerQuerySockets {
			log.Warnf("-udp-accept-errors only applies when -udp-per-query-sockets is enabled; flag has no effect in shared socket mode")
		} else {
			log.Warnf("forged response filtering is disabled; the first DNS response will be accepted regardless of RCODE - connections may fail under active DNS injection")
		}
	}
	// Build tunnel server config.
	ts, err := client.NewTunnelServer(domainArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	ts.ClientIDSize = clientIDSize
	ts.MaxQnameLen = maxQnameLen
	ts.MaxNumLabels = maxNumLabels
	ts.RPS = rpsLimit
	ts.RecordType = recordTypeStr

	// Build tunnel.
	tunnel, err := client.NewTunnel(resolver, ts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	tunnel.IdleTimeout = idleTimeout
	tunnel.KeepAlive = keepAlive
	tunnel.OpenStreamTimeout = openStreamTimeout
	tunnel.ReconnectMinDelay = reconnectMinDelay
	tunnel.ReconnectMaxDelay = reconnectMaxDelay
	tunnel.PollDelay = pollDelay
	tunnel.ActivePollDelay = activePollDelay
	tunnel.PollMaxDelay = pollMaxDelay
	tunnel.UDPTransportStaleTimeout = udpTransportStaleTimeout
	tunnel.OpenStreamFailureLimit = openStreamFailureLimit
	tunnel.PacketQueueSize = queueSize
	tunnel.KCPWindowSize = kcpWindowSize
	tunnel.QueueOverflowMode = queueOverflowMode

	if rpsLimit > 0 {
		log.Infof("DNS query rate limited to %.1f queries/sec", rpsLimit)
	}

	err = tunnel.ListenAndServe(listenAddr)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
