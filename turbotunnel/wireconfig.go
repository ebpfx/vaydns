package turbotunnel

// WireConfig holds wire protocol parameters for the VayDNS upstream format.
type WireConfig struct {
	// ClientIDSize is the number of bytes used for the ClientID on the wire.
	// Default is 2.
	ClientIDSize int
}

// DataOverhead returns the number of bytes consumed by per-query framing
// (ClientID, length prefix) before the actual data payload.
func (wc WireConfig) DataOverhead() int {
	size := wc.ClientIDSize
	if size <= 0 {
		size = 2
	}
	return size + 1
}

// MaxDataLen returns the maximum number of data bytes that can be carried
// in a single upstream query packet.
func (wc WireConfig) MaxDataLen() int {
	return 255
}
