package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"netgopha/stream"

	"github.com/fatih/color"
)

// TLSClient begins the Client with TLS encryption
func TLSClient(protocol string, serverCert string, remoteAddr string, nodata bool, program string) {

	// Begin TLS parse & configuration
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(serverCert))
	if !ok {
		log.Fatal("[!] Failed to parse root certificate")
	}
	config := &tls.Config{RootCAs: roots, InsecureSkipVerify: true}

	// Start TLS connection
	conn, err := tls.Dial(protocol, remoteAddr, config)
	if err != nil {
		log.Fatal(err)
	}
	color.Blue("[+] TLS encrypted: Connected to %s", remoteAddr)
	if program == "" {
		stream.TCPConnHandle(conn, nodata)
	} else {
		if runtime.GOOS == "windows" {
			stream.ExecProgramWindows(conn, program)
		} else {
			stream.ExecProgramLinux(conn, program)
		}
	}
}

// Client relies on Transferstreams to write input and output
func Client(protocol string, RemoteServer string, RemotePort string, encrypted bool, nodata bool, program string) {

	remoteAddr := RemoteServer + ":" + RemotePort

	// If not encrypted, no TLS
	if !encrypted {
		conn, err := net.Dial(protocol, remoteAddr)
		if err != nil {
			log.Fatalln(err)
		}
		color.Blue("[+] Unecrypted: Connected to %s", remoteAddr)
		if program == "" {
			stream.TCPConnHandle(conn, nodata)
		} else {
			if runtime.GOOS == "windows" {
				stream.ExecProgramWindows(conn, program)
			} else {
				stream.ExecProgramLinux(conn, program)
			}
		}
	} else {

		// This checks if we are using a server.pem
		NewServerCert := stream.CheckCerts("cert.pem")
		if NewServerCert != "" {
			color.Blue("[+] Starting encrypted client connection with cert.pem")
			TLSClient(protocol, NewServerCert, remoteAddr, nodata, program)
		} else {
			color.Blue("[+] Starting encrypted client connection with hardcoded certs")
			TLSClient(protocol, serverCert, remoteAddr, nodata, program)
		}
	}
}

// ListenServer starts a TCP listener
func ListenServer(protocol string, server string, port string, encrypted bool, program string) {

	// The listen address:
	// e.g. 127.0.0.1:8080
	// e.g. :8080
	listenAddr := server + ":" + port

	// If unencrypted, then start without TLS
	if !encrypted {
		ln, err := net.Listen(protocol, listenAddr)
		if err != nil {
			color.Red("[!] Unecrypted listener unable to start: %s", err)
			return
		}
		color.Blue("[+] Starting unecrypted listener on %s", listenAddr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
			}
			if program == "" {
				//Connection, nodata, listener
				stream.TCPConnHandle(conn, false)
			} else {
				if runtime.GOOS == "windows" {
					stream.ExecProgramWindows(conn, program)
				} else {
					stream.ExecProgramLinux(conn, program)
				}
			}
		}
	} else {
		for {
			// Read files to check for user supplied server.key and cert.pem
			NewServerKey := stream.CheckCerts("server.key")
			NewServerCert := stream.CheckCerts("cert.pem")

			// If return value is not empty then use that for TLS server
			if NewServerKey != "" && NewServerCert != "" {
				color.Blue("[+] Starting encrypted listener with cert files on %s", listenAddr)
				stream.StartTLSServer(protocol, NewServerKey, NewServerCert, listenAddr, program)
			} else {
				// Use the hardcoded certs
				color.Blue("[+] Starting encrypted listener with hardcoded certs on %s", listenAddr)
				stream.StartTLSServer(protocol, serverKey, serverCert, listenAddr, program)
			}
		}
	}
}

// CheckProtocol determines if IPv4, IPv6 selected
func CheckProtocol(ver4 bool, ver6 bool) string {
	if ver4 {
		return "tcp"
	} else if ver6 {
		return "tcp6"
	} else {
		return "tcp"
	}
}

// Lookup IP of hostname
func resolveHost(host string) []string {

	resolvedIP, err := net.LookupHost(host)
	if err != nil {
		color.Red("[!] Unable to resolve hostname")
	}

	return resolvedIP

}

// Check if IP or hostname
func checkIP(host string) bool {

	addr := net.ParseIP(host)
	if addr == nil {
		// host is a hostname
		return false
	}
	// host is a IP address
	return true
}

func main() {

	// Start flag parser

	// Strings
	var host string            // Does not require flag, argument only
	var destinationPort string // Does not require flag, argument only
	var listenHost string
	var localPort string
	var exec string

	flag.StringVar(&listenHost, "s", "", "IP address to listen on")
	flag.StringVar(&localPort, "p", "", "Local port to listen on")
	flag.StringVar(&exec, "e", "", "Execute command locally")

	// Bool
	var version bool
	var encrypted bool
	var listen bool
	var noresolve bool
	var nodata bool
	var ver4 bool
	var ver6 bool

	flag.BoolVar(&version, "v", false, "Show current version")
	flag.BoolVar(&encrypted, "x", false, "Use TLS encryption.  If server.key/cert.pem not found, use hardcoded values.")
	flag.BoolVar(&listen, "l", false, "Listen mode")
	flag.BoolVar(&noresolve, "n", false, "Do not resolve domain")
	flag.BoolVar(&nodata, "z", false, "Do not send any data")
	flag.BoolVar(&ver4, "4", false, "Force IPv4")
	flag.BoolVar(&ver6, "6", false, "Force IPv6")

	flag.Parse()

	// End flag parser

	// If no arguments then display help
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		fmt.Println("netgopha [-l] [-e] [-p listen port ] [-e aes password] [-s listen ip address] [ip/hostname] [port]")
		flag.Usage()
		os.Exit(1)
	}

	// Print current version and exit
	if version {
		color.Blue(NetgophaVersion)
		os.Exit(0)
	}

	// Define protocol (default is tcp)
	proto := CheckProtocol(ver4, ver6)

	// If not listen mode, then client mode
	if !listen {

		// Missing IP/hostname or port (or both)
		if flag.NArg() < 2 {
			color.Red("(arguments) [ip/hostname] [port] are mandatory to connect")
			os.Exit(1)
		}

		// Check if destination port is empty or an integer
		if _, err := strconv.Atoi(flag.Arg(1)); err != nil {
			color.Red("Destination port is empty or does not have integer value")
			os.Exit(1)
		}

		// Define host as argument 1 and destination port as argument 2
		host = flag.Arg(0)
		destinationPort = flag.Arg(1)

		// Check if we are dealing with an IP address or hostname
		color.Blue("[+] Checking if host or IP: %s", host)
		isIP := checkIP(host)
		if isIP {
			color.Blue("[+] %s is IP: %t", host, isIP)
		}

		// Resolve hostname if we have a hostname and "noresolve" is not enabled
		if !isIP && !noresolve {
			resolvedIP := resolveHost(host)
			if resolvedIP != nil {
				color.Blue("[+] Resolved IP: %s", resolvedIP[0])
				// Start client mode with resolved IP
				Client(proto, string(resolvedIP[0]), destinationPort, encrypted, nodata, exec)
			}
		}

		// Start client mode
		Client(proto, host, destinationPort, encrypted, nodata, exec)
	}

	// Check for listen mode
	if listen {

		// Check if listen port is an integer or emtpy
		if _, err := strconv.Atoi(localPort); err != nil {
			color.Red("Listen port shall be not empty and have integer value")
			os.Exit(1)
		}

		// Start listener
		if listenHost != "" {
			ListenServer(proto, listenHost, localPort, encrypted, exec) // If -s, then set IP of listener
		} else {
			ListenServer(proto, "", localPort, encrypted, exec)
		}
	}

	if destinationPort != "" {
		color.Blue("[+] Port: %s", destinationPort)
	}
}
