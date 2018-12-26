// Package sockets provides helper functions to create and configure Unix or TCP sockets.
package sockets

import (
	"net"

	csptls "github.com/hyperledger/fabric/bccsp/tls"
)

// NewTCPSocket creates a TCP socket listener with the specified address and
// the specified tls configuration. If TLSConfig is set, will encapsulate the
// TCP listener inside a TLS one.
func NewTCPSocket(addr string, tlsConfig *csptls.Config) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		tlsConfig.NextProtos = []string{"http/1.1"}
		l = csptls.NewListener(l, tlsConfig)
	}
	return l, nil
}
