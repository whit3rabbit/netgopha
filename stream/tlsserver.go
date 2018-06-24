package stream

import (
	"crypto/tls"
	"log"

	"github.com/fatih/color"
)

// StartTLSServer begins the TLS server
func StartTLSServer(protocol string, serverKey string, serverCert string, listenAddr string, program string) {

	// TLS stuff (serverCert & serverKey)
	cer, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	// Start the encrypted listener
	ln, err := tls.Listen(protocol, listenAddr, config)
	if err != nil {
		color.Red("[!] Encrypted listener unable to start: %s", err)
		return
	}
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}

	// Check if we need to execute a program
	if program == "" {
		// Program string was empty
		TCPConnHandle(conn, false)
	} else {
		ExecProgram(conn, program)
	}
}
