package udpaddr

import (
	"fmt"
	"net"
	"strings"
)

// Normalize returns addr with a default DNS port appended when the caller
// omitted one. Explicit ports are preserved.
func Normalize(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("empty UDP address")
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return net.JoinHostPort(strings.Trim(addr, "[]"), "53"), nil
	}
	if strings.Count(addr, ":") > 1 {
		return net.JoinHostPort(addr, "53"), nil
	}
	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("invalid UDP address %q", addr)
	}
	return net.JoinHostPort(addr, "53"), nil
}
