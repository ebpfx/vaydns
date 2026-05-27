module github.com/net2share/vaydns

go 1.24.4

require (
	github.com/sirupsen/logrus v1.9.4
	github.com/xtaci/kcp-go/v5 v5.6.61
	github.com/xtaci/smux v1.5.50
)

require (
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

replace github.com/xtaci/kcp-go/v5 => github.com/net2share/kcp-go/v5 v5.0.0-20260325165956-416ba9d3856d

replace github.com/xtaci/smux => github.com/nxdp/smux v1.5.50
