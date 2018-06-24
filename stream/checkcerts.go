package stream

import (
	"io/ioutil"
	"os"

	"github.com/fatih/color"
)

// CheckCerts attempts to read server.key and cert.pem for TLS
// if those files exists. Then it returns the values for the
// certs as a string.  If error it returns nothing as a string
func CheckCerts(cert string) string {

	// Check if file exists
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		color.Blue("[+] File found: %s", cert)
		CertRead, err := ioutil.ReadFile(cert)
		// Error return nothing
		if err != nil {
			color.Red("[!] Could not read %s. Using hardcoded values", cert)
			return ""
		}
		// Sucessfully read cert file.  Return
		return string(CertRead)
	}
	color.Red("[+] File not found: %s", cert)
	return ""
}
