// +build !go1.7

package tlsconfig

import (
	//"crypto/x509"
	cspx509 "github.com/hyperledger/fabric/bccsp/x509"

)

// SystemCertPool returns an new empty cert pool,
// accessing system cert pool is supported in go 1.7
func SystemCertPool() (*cspx509.CertPool, error) {
	return cspx509.NewCertPool(), nil
}
