// +build go1.5

// Package tlsconfig provides primitives to retrieve secure-enough TLS configurations for both clients and servers.
//
package tlsconfig

// Client TLS cipher suites (dropping CBC ciphers for client preferred suite set)
var clientCipherSuites = []uint16{
	csptls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	csptls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	csptls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	csptls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}
