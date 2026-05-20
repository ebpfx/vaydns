# Client Library

The `client` package provides a reusable Go library for building DNS tunnel clients.

## Import

```go
import "github.com/net2share/vaydns/client"
```

## Usage

There are two ways to use the library:

### Step-by-step API

For embedding in frameworks like xray-core where you need control over each layer:

```go
r, _ := client.NewResolver("8.8.8.8:53")
ts, _ := client.NewTunnelServer("t.example.com")
t, _ := client.NewTunnel(r, ts)

t.InitiateResolverConnection()
t.InitiateDNSPacketConn(ts.Addr)
t.InitiateKCPConn(ts.MTU)
t.InitiateSmuxSession()

stream, _ := t.OpenStream() // returns net.Conn
defer t.Close()
```

Each `Initiate*` method sets up one layer of the protocol stack. `OpenStream()` returns a `net.Conn` that can be used like any TCP connection.

### Managed API

For standalone clients that need automatic session management and reconnection:

```go
r, _ := client.NewResolver("8.8.8.8:53")
ts, _ := client.NewTunnelServer("t.example.com")
t, _ := client.NewTunnel(r, ts)

t.ListenAndServe("127.0.0.1:10888") // blocks, handles reconnection
```

`ListenAndServe` opens a local TCP listener, creates tunnel sessions with automatic reconnection on failure, and forwards connections through the tunnel.

## Key types

| Type | Description |
|------|-------------|
| `Resolver` | DNS transport configuration for UDP |
| `TunnelServer` | Server domain + wire protocol settings |
| `Tunnel` | Main tunnel connection with session and timeout configuration |
| `Outbound` | High-level API for multiple resolver/server pairs |

## Configuration

All configuration is done through struct fields before calling `Initiate*` or `ListenAndServe`:

```go
// Resolver options
r.DialerControl = controlFunc                   // socket options callback (SO_MARK, SO_BINDTODEVICE, etc.)
r.UDPWorkers = 200                              // concurrent UDP workers
r.UDPSharedSocket = true                        // single socket mode; CLI default
r.UDPTimeout = 800 * time.Millisecond           // per-query timeout
r.UDPAcceptErrors = true                        // accept non-NOERROR responses (disables forged filtering)

// Tunnel server options
ts.ClientIDSize = 1      // smaller ClientID
ts.MaxQnameLen = 63      // QNAME length constraint
ts.MaxNumLabels = 1      // label count constraint
ts.RPS = 200             // rate limit queries/second
ts.RecordType = "cname"  // DNS record type for downstream data: txt, null, hinfo, cname, a, aaaa, mx, ns, srv, cert, https, caa (default: "txt")

// Session options
t.IdleTimeout = 60 * time.Second
t.KeepAlive = 10 * time.Second
t.OpenStreamTimeout = 10 * time.Second
t.SessionCheckInterval = 500 * time.Millisecond
t.ReconnectMinDelay = 1 * time.Second
t.ReconnectMaxDelay = 30 * time.Second
t.PollDelay = 500 * time.Millisecond
t.ActivePollDelay = 200 * time.Millisecond
t.PollMaxDelay = 2 * time.Second
t.UDPTransportStaleTimeout = 3 * time.Second
t.OpenStreamFailureLimit = 3

// Transport queue options
t.PacketQueueSize = 512                                // queue capacity
t.KCPWindowSize = 256                                  // KCP window (0 = queue-size/2)
t.QueueOverflowMode = turbotunnel.QueueOverflowDrop    // "drop" or "block"
```

Zero values use sensible defaults. See the [README](../README.md) for flag descriptions — each flag maps directly to a struct field.
