# VayDNS

Userspace DNS tunnel with plaintext UDP transport.

> VayDNS is a fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield, with protocol optimizations and additional features. The transport and wire protocol have diverged and are no longer compatible with upstream dnstt.

## Features

- **Plain UDP transport** — direct DNS queries with per-query socket rotation
- **Reliable delivery** — KCP/smux session protocol with automatic retransmission
- **Lean transport stack** — smux directly over KCP to minimize per-packet overhead
- **Censorship resistance** — per-query UDP sockets with forged-response filtering
- **Auto-recovery** — client automatically reconnects on session failure

## Architecture

```
.------.  |            .---------.             .------.
|tunnel|  |            | public  |             |tunnel|
|client|<---UDP DNS--->|recursive|<--UDP DNS-->|server|
'------'  |c           |resolver |             '------'
   |      |e           '---------'                |
.------.  |n                                   .------.
|local |  |s                                   |remote|
| app  |  |o                                   | app  |
'------'  |r                                   '------'
```

VayDNS is an application-layer tunnel that runs in userspace. It connects a local TCP port to a remote TCP port by way of a DNS resolver. It does not provide a TUN/TAP interface or a built-in proxy — pair it with a SOCKS or HTTP proxy on the server side.

## Quick start

### 1. Build

```sh
go build -o vaydns-server ./vaydns-server
go build -o vaydns-client ./vaydns-client
```

### 2. Run the server

```sh
./vaydns-server -udp :5300 -domain t.example.com -upstream 127.0.0.1:8000
```

You also need something for the server to forward to (a proxy, SSH, etc.). For testing, use an Ncat listener:

```sh
ncat -l -k -v 127.0.0.1 8000
```

### 3. Run the client

Choose a public UDP resolver, or point the client directly at your own server with `-udp`.

Using plaintext UDP (no covertness):

```sh
./vaydns-client -udp 8.8.8.8:53 \
  -domain t.example.com -listen 127.0.0.1:7000
```

### 4. Test

```sh
ncat -v 127.0.0.1 7000
```

## DNS zone setup

The server acts as an authoritative nameserver, so you need a domain with an NS record pointing to it. For example, if your domain is `example.com` and your server IP is `203.0.113.2`:

| Type | Name            | Value           |
| ---- | --------------- | --------------- |
| A    | tns.example.com | 203.0.113.2     |
| AAAA | tns.example.com | 2001:db8::2     |
| NS   | t.example.com   | tns.example.com |

- `tns` is the glue record pointing to your server's IP
- `t` is the tunnel subdomain (keep it short to maximize payload space)
- `tns` must **not** be a subdomain of `t`

Queries for `*.t.example.com` will now be forwarded to your tunnel server.

### Port forwarding

The server needs to receive DNS on port 53. Rather than running as root, listen on an unprivileged port and redirect:

```sh
sudo iptables -I INPUT -p udp --dport 5300 -j ACCEPT
sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
sudo ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT
sudo ip6tables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
```

## Configuration reference

### Server flags

| Flag                 | Description                                | Default    |
| -------------------- | ------------------------------------------ | ---------- |
| `-udp ADDR`          | Listen address for UDP DNS                                        | (required) |
| `-domain NAME`       | Tunnel domain                                                     | (required) |
| `-upstream ADDR`     | Forward tunnel streams to this TCP address                        | `127.0.0.1:10888` |
| `-mtu N`             | Max UDP payload size for responses                                | `1232`     |
| `-idle-timeout D`    | Session idle timeout (must match client)                          | `10s`      |
| `-keepalive D`       | Keepalive ping interval (must match client, must be < idle-timeout) | `2s`      |
| `-clientid-size N`   | ClientID size in bytes                                              | `1`        |
| `-record-type TYPE`  | DNS record type for downstream data: `null`, `txt`, `hinfo`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`, `cert`, `https`, `caa`. Must match the client. | `null`     |
| `-queue-size N`      | Packet queue size for transport and DNS layers                    | `512`      |
| `-kcp-window-size N` | KCP send/receive window size in packets (0 = queue-size/2)        | `0`        |
| `-queue-overflow MODE` | Queue overflow behavior: `drop` (silent discard) or `block` (backpressure) | `drop`     |
| `-response-queue-size N` | Pending DNS response queue size (0 = `queue-size`)            | `0`        |
| `-response-workers N` | Number of DNS response sender workers                            | `2`        |
| `-response-delay D`  | Max time to hold a DNS response open while waiting for downstream data | `500ms` |
| `-log-level LEVEL`   | Log level: debug, info, warning, error                            | `info`     |

> **Note:** The server response queue is drop-based. When it fills, pending DNS responses are dropped and counted in the debug stats log as `response_dropped`.

### Client flags

#### Transport (pick one)

| Flag        | Description                                      |
| ----------- | ------------------------------------------------ |
| `-udp ADDR` | Use plaintext UDP DNS (no covertness)            |

#### Required

| Flag                | Description                                                     |
| ------------------- | --------------------------------------------------------------- |
| `-domain NAME`      | Tunnel domain                                                   |
| `-listen ADDR`      | Local TCP listen address                                        | `127.0.0.1:10888` |

#### Session and recovery

| Flag                        | Description                                        | Default |
| --------------------------- | -------------------------------------------------- | ------- |
| `-idle-timeout D`           | Session idle timeout (must match server)                                                    | `10s`   |
| `-keepalive D`              | Keepalive ping interval (must match server, must be < idle-timeout)                         | `2s`   |
| `-open-stream-timeout D`    | Timeout for opening an smux stream                                                          | `10s`   |
| `-open-stream-failure-limit N` | Retire an idle session after this many consecutive stream-open failures                  | `3`   |
| `-reconnect-min D`          | Initial backoff delay for session reconnect                                                  | `1s`    |
| `-reconnect-max D`          | Max backoff delay (must be >= reconnect-min)                                                 | `30s`   |
| `-udp-transport-stale-timeout D` | Retire the current session if per-query UDP sees no valid response for this long while streams need transport | `15s` |

> **Note:** `idle-timeout` and `keepalive` must be set to the same values on both client and server — mismatched values will cause one side to close the session before the other detects it. Keep `keepalive` well below `idle-timeout` (the default 5x ratio allows ~5 ping attempts before timeout).
>
> **How they relate:** `keepalive` controls how often smux sends ping frames to prove the session is alive. `idle-timeout` is how long smux waits with no received data (including pings) before declaring the session dead — it applies symmetrically on both sides.

#### UDP transport tuning

These flags only apply when using `-udp`. By default, each query is sent through a shared UDP socket.

| Flag                 | Description                                                                                                                                                | Default |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `-udp-workers N`     | Concurrent UDP worker goroutines                                                                                                                           | `100`   |
| `-udp-timeout D`     | Per-query response timeout — the total time a worker waits for a valid (NOERROR) response. Forged responses are discarded but the deadline is not extended — if no valid response arrives within this window, the query is abandoned. | `800ms` |
| `-udp-per-query-sockets` | Use per-query UDP sockets instead of the default shared socket. With this flag, each query is sent from a new socket with a random ephemeral source port, making the tunnel harder to fingerprint or block by port. Without it, all queries share one socket and source port for the lifetime of the client — blocking that port kills the tunnel. | `false` |
| `-udp-accept-errors` | In per-query mode, accept the first DNS response regardless of RCODE instead of waiting for a NOERROR response. This disables forged response filtering — the worker stops waiting after the first forged response, so the real response is likely lost. Only useful for debugging; not recommended in production. Ignored when `-udp-per-query-sockets` is not set. | `false` |
| `-poll-delay D`      | Base delay before sending an empty DNS poll when idle                                                                                                      | `500ms` |
| `-active-poll-delay D` | Poll delay cap while streams are active or being opened                                                                                                  | `200ms` |
| `-poll-max-delay D`  | Max idle backoff between empty DNS polls                                                                                                                   | `1s`    |

#### Queue and KCP tuning

These flags apply to the UDP transport on the client side. The server has the same flags where applicable.

| Flag                   | Description                                                        | Default |
| ---------------------- | ------------------------------------------------------------------ | ------- |
| `-queue-size N`        | Packet queue size for transport and DNS layers                     | `512`   |
| `-kcp-window-size N`   | KCP send/receive window size in packets (0 = queue-size/2). Must be <= queue-size. | `0`     |
| `-queue-overflow MODE` | Queue overflow behavior: `drop` (silent discard, KCP retransmits) or `block` (backpressure). | `drop`  |

> **Note:** `drop` is the correct default for most deployments. It matches the original dnstt design where KCP handles retransmission of locally dropped packets. `block` mode applies backpressure instead of dropping — this can help in some censored network conditions but may slow down UDP transport significantly. Both client and server can use different modes independently.

#### QNAME constraints

Some resolvers reject queries with long QNAMEs or too many labels.

| Flag                | Description                                                                 | Default |
| ------------------- | --------------------------------------------------------------------------- | ------- |
| `-max-qname-len N`  | Max total QNAME length in wire format (0 = RFC 1035 max of 253)             | `63`    |
| `-max-num-labels N` | Max data labels before the tunnel domain (0 = unlimited, 1 = most DNS-like) | `1`     |

These reduce upstream throughput but improve compatibility. The minimum effective MTU is 25 bytes — below that the client exits with an error.

> **How these interact:** The client computes the upstream MTU from the tunnel domain length, `max-qname-len`, and `max-num-labels`. The relationship is:
>
> ```
> maxQnameLen >= dataLabelWireBytes + domainWireLen
> ```
>
> Where `domainWireLen` is the wire-format length of the tunnel domain (`1 + len` per label — e.g. `t.example.com` = 14 bytes), and the client subtracts upstream framing overhead from the raw base32 capacity to derive the KCP MTU (`clientid-size + 1` bytes, so 2 bytes by default). With a domain like `t.example.com`, the default `max-qname-len=63` still yields usable MTU headroom. The client exits if the resulting MTU falls below 25 bytes.

#### Other

| Flag               | Description                                                | Default         |
| ------------------ | ---------------------------------------------------------- | --------------- |
| `-rps N`           | Rate limit outgoing DNS queries per second (0 = unlimited). Uses a token bucket with 1-second burst allowance. | `0`             |
| `-clientid-size N` | ClientID size in bytes | `1`             |
| `-record-type TYPE` | DNS record type for downstream data: `null`, `txt`, `hinfo`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`, `cert`, `https`, `caa`. Must match the server. | `null`          |
| `-log-level LEVEL` | Log level: debug, info, warning, error                     | `info`          |

## Proxy examples

VayDNS is only a tunnel — pair it with a proxy server for web browsing.

### HTTP proxy (Ncat)

> Ncat's proxy is not intended for use by untrusted clients — it won't prevent them from connecting to localhost ports on the server.

```sh
# Server
ncat -l -k --proxy-type http 127.0.0.1 8000
./vaydns-server -udp :5300 -domain t.example.com -upstream 127.0.0.1:8000

# Client
./vaydns-client -udp 8.8.8.8:53 -domain t.example.com -listen 127.0.0.1:7000
curl --proxy http://127.0.0.1:7000/ https://wtfismyip.com/text
```

### SOCKS5 proxy (SSH)

Server-side SOCKS (accessible to anyone with tunnel access):

```sh
# Server
ssh -N -D 127.0.0.1:8000 -o NoHostAuthenticationForLocalhost=yes 127.0.0.1
./vaydns-server -udp :5300 -domain t.example.com -upstream 127.0.0.1:8000

# Client
./vaydns-client -udp 8.8.8.8:53 -domain t.example.com -listen 127.0.0.1:7000
curl --proxy socks5h://127.0.0.1:7000/ https://wtfismyip.com/text
```

Client-side SOCKS (private, SSH through the tunnel). Ensure `AllowTcpForwarding yes` (default) is set in sshd_config. The `HostKeyAlias` option lets SSH verify the host key when connecting through the tunnel:

```sh
# Server — forward directly to SSH
./vaydns-server -udp :5300 -domain t.example.com -upstream 127.0.0.1:22

# Client — tunnel SSH, then SOCKS through SSH
./vaydns-client -udp 8.8.8.8:53 -domain t.example.com -listen 127.0.0.1:8000
ssh -N -D 127.0.0.1:7000 -o HostKeyAlias=tunnel-server -p 8000 127.0.0.1
curl --proxy socks5h://127.0.0.1:7000/ https://wtfismyip.com/text
```

### Tor bridge

```sh
# Server (ORPort 9001)
./vaydns-server -udp :5300 -domain t.example.com -upstream 127.0.0.1:9001

# Client
./vaydns-client -udp 8.8.8.8:53 -domain t.example.com -listen 127.0.0.1:7000
```

Add to `/etc/tor/torrc` or Tor Browser (`FINGERPRINT` from `/var/lib/tor/fingerprint`):

```
Bridge 127.0.0.1:7000 FINGERPRINT
```

System tor SOCKS port: `127.0.0.1:9050`. Tor Browser: `127.0.0.1:9150`.

## Security

### Transport security

Protocol stack:

```text
application data
smux              (stream multiplexing)
KCP               (reliable delivery over datagrams)
DNS messages
UDP DNS transport
```

VayDNS does not add end-to-end confidentiality or authentication to the tunnel payloads. The DNS transport is plain UDP, so anyone on the path can inspect the resolver traffic.

### Covertness

The UDP transport is visible to local network observers. An observer can likely infer from traffic volume that a tunnel is being used, and can also see the resolver destination.

Observers between the resolver and the tunnel server, including the resolver itself, can identify the tunnel, its destination, and its contents.

An observer watching traffic leaving the tunnel server can see any unprotected data the server forwards. To protect this leg, use your own application-layer security inside the tunnel.

### Payload sizes

Upstream (client -> server) payload depends on the domain name length. Shorter domains = more space.

Downstream (server -> client) payload depends on the UDP response size. The `-mtu` flag on the server controls the max UDP payload:

```sh
./vaydns-server -mtu 512 -udp :5300 -domain t.example.com -upstream 127.0.0.1:8000
```

- Default: `1232` bytes (safe for most EDNS(0) resolvers)
- Max practical: `1452` (above this, IP fragmentation may hurt performance)
- Min compatible: `512` (reduced bandwidth)

Both client and server log their effective MTU at startup. The server's effective MTU is the minimum guaranteed across all responses (some responses may have more space depending on the query size).

### Record types

VayDNS supports multiple DNS record types for downstream data encoding. Both client and server must use the same `-record-type`. The default is `null`.

| Type | Description | Capacity |
| ---- | ----------- | -------- |
| `null` | NULL record (default). Raw binary payload in a single RR. Some recursive resolvers may filter or refuse to relay NULL records. | Bounded by UDP payload |
| `txt` | TXT record. Highest capacity. | Bounded by UDP payload (~1200 bytes) |
| `hinfo` | HINFO record. Payload split across CPU and OS character-string fields. | 510 bytes |
| `cname` | CNAME record. Data encoded as a DNS name under the tunnel domain. | Bounded by 255-byte DNS name limit |
| `ns` | NS record. Same encoding as CNAME. | Same as CNAME |
| `mx` | MX record. 2-byte preference header + name encoding. | Same as CNAME |
| `srv` | SRV record. 6-byte header + name encoding. | Same as CNAME |
| `a` | A records. Data split into 4-byte chunks across multiple answer RRs. | Bounded by UDP payload |
| `aaaa` | AAAA records. Data split into 16-byte chunks across multiple answer RRs. | Bounded by UDP payload |
| `cert` | CERT record. 5-byte fixed header plus opaque certificate data. | Bounded by UDP payload |
| `https` | HTTPS record. 2-byte SvcPriority header plus name encoding. | Same as CNAME |
| `caa` | CAA record. Payload encoded in the value portion of a fixed `issue` property. | Bounded by UDP payload |

## Client library

The `client` package (`github.com/net2share/vaydns/client`) provides a reusable Go library for embedding VayDNS in other applications. See [docs/client-library.md](docs/client-library.md) for usage and examples.

## E2E tests

End-to-end tests run the full tunnel stack in Docker containers. Requires Docker.

```sh
# Run all tests
bash e2e/run-test.sh

# Or individually
bash e2e/tunnel/run.sh           # basic tunnel (NULL, default)
bash e2e/tunnel/run.sh cname     # tunnel with CNAME records
bash e2e/socks-download/run.sh   # 10MB file download via SOCKS5
bash e2e/recovery/run.sh         # server crash recovery
```

## License

VayDNS is a fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield. The original dnstt is public domain.
