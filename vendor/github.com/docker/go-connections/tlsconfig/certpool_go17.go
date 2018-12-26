// +build go1.7

package tlsconfig

import (
//	"crypto/x509"
	"runtime"
	cspx509 "github.com/hyperledger/fabric/bccsp/x509"
)

// SystemCertPool returns a copy of the system cert pool,
// returns an error if failed to load or empty pool on windows.
func SystemCertPool() (*cspx509.CertPool, error) {
	certpool, err := cspx509.SystemCertPool()
	if err != nil && runtime.GOOS == "windows" {
		return cspx509.NewCertPool(), nil
	}
	return certpool, err
}
