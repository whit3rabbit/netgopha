package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/whit3rabbit/netgopha/execute"
	"github.com/fatih/color"
)

// NetgophaVersion is Current version
const NetgophaVersion = "0.1"

// TLS Server Keys for encrypted communicaton
// http://pascal.bach.ch/2015/12/17/from-tcp-to-tls-in-go/
//
// netgopha will check for a server.key or cert.pem file and use
// that before using the hardcoded keys below.
// You could remove the private key (server key) and leave the
// hardcoded serverCert if you only want to use as a client.
// To generate keys:
// openssl ecparam -genkey -name prime256v1 -out server.key
// openssl req -new -x509 -key server.key -out cert.pem -days 3650

// server.key (change this or generate server.key file)
var serverKey = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGb7E70UCFJbOtauKvoMJBKt8duVCSt1iMXF44uETK4XoAoGCCqGSM49
AwEHoUQDQgAEHG/mYyHLPII3AeEjNExn3bx3xOKc3p1lND82XeszXTEf535EtZos
f1GIGj1AxGCmwZIUDzAqLheUmTAsQP5FsA==
-----END EC PRIVATE KEY-----
`

// cert.pem (change this or generate cert.pem file)
var serverCert = `-----BEGIN CERTIFICATE-----
MIICJjCCAc6gAwIBAgIJAIwUhparoU7MMAkGByqGSM49BAEwRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAeFw0xNzExMTkwNDQyMTVaFw0yNzExMTcwNDQyMTVaMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQcb+Zj
Ics8gjcB4SM0TGfdvHfE4pzenWU0PzZd6zNdMR/nfkS1mix/UYgaPUDEYKbBkhQP
MCouF5SZMCxA/kWwo4GnMIGkMB0GA1UdDgQWBBSiIMId3fHKOW1O3MIlwG9vQP7v
8zB1BgNVHSMEbjBsgBSiIMId3fHKOW1O3MIlwG9vQP7v86FJpEcwRTELMAkGA1UE
BhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZIIJAIwUhparoU7MMAwGA1UdEwQFMAMBAf8wCQYHKoZIzj0E
AQNHADBEAiBp1gKDtuMRREyn/Z2/ouOMW0RoD1BwAkR7vkY4f/90nQIgKVJB8ZgQ
FdbP1FZBpEK/FoH79kE2CWbm63UdzTDaRWM=
-----END CERTIFICATE-----
`

// ExecProgram for TCP Listener...client sends program
// it wants to execute on listener.  Listener waits for
func ExecProgram(conn net.Conn, program string) {

	// Unix style systems
	cmd := exec.Command(program)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = conn // STDOUT is network connection
	cmd.Stdin = conn
	cmd.Stderr = conn

	color.Blue("Executing program %s", program)
	err := cmd.Run()
	if err != nil {
		color.Red("[!] Error running program %s = %v", program, err)
		color.Red("[!] Exiting")
		os.Exit(1)
	}

	color.Blue("Starting connection")
	chanToStdout := streamCopy(conn, cmd.Stdout)
	chanToRemote := streamCopy(cmd.Stdin, conn)
	select {
	case <-chanToStdout:
		color.Red("[!] Remote connection is closed")
		conn.Close()
		os.Exit(1)
	case <-chanToRemote:
		color.Red("[!] Local program is terminated")
		conn.Close()
		os.Exit(1)
	}
}

// TCPConnHandle = TCP -> Stdout and Stdin -> TCP
// https://github.com/vfedoroff/go-netcat/blob/master/main.go
func TCPConnHandle(con net.Conn, nodata bool) {

	if !nodata {
		// Remote -> Client
		chanToStdout := streamCopy(con, os.Stdout)
		// Client -> Remote
		chanToRemote := streamCopy(os.Stdin, con)
		select {
		case <-chanToStdout:
			color.Red("[!] Remote connection is closed")
			con.Close()
			os.Exit(1)
		case <-chanToRemote:
			color.Red("[!] Local program is terminated")
			con.Close()
			os.Exit(1)
		}
	} else {
		// Don't send any data, just the STDOUT
		// Remote -> Client
		chanToStdout := streamCopy(con, os.Stdout)
		select {
		case <-chanToStdout:
			color.Red("[!] Remote connection is closed")
			con.Close()
			os.Exit(1)
		}
	}
}

// streamCopy is the sync between OS and stream
// https://github.com/vfedoroff/go-netcat/blob/master/main.go
func streamCopy(src io.Reader, dst io.Writer) <-chan int {

	// Create 1024 byte transfer buffer
	buf := make([]byte, 1024)
	syncChannel := make(chan int)

	go func() {
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				con.Close()
				color.Red("[!] Connection from %v is closed\n", con.RemoteAddr())
			}
			syncChannel <- 0 // Notify that processing is finished
		}()

		for {

			var nBytes int
			var err error

			// io.Reader.Read(buf) -> buffer
			nBytes, err = src.Read(buf)
			if err != nil {
				if err != io.EOF {
					color.Red("[!] Read error: %s\n", err)
				}
				break
			}

			// io.Writer.Write(buf)
			_, err = dst.Write(buf[0:nBytes])
			if err != nil {
				color.Red("[!] Write error: %s\n", err)
			}
		}
	}()

	return syncChannel

}

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
		TCPConnHandle(conn, nodata)
	} else {
		ExecProgram(conn, program)
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
			TCPConnHandle(conn, nodata)
		} else {
			ExecProgram(conn, program)
		}
	} else {

		// This checks if we are using a server.pem
		NewServerCert := CheckCerts("cert.pem")
		if NewServerCert != "" {
			color.Blue("[+] Starting encrypted client connection with cert.pem")
			TLSClient(protocol, NewServerCert, remoteAddr, nodata, program)
		} else {
			color.Blue("[+] Starting encrypted client connection with hardcoded certs")
			TLSClient(protocol, serverCert, remoteAddr, nodata, program)
		}
	}
}

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
				TCPConnHandle(conn, false)
			} else {
				ExecProgram(conn, program)
			}
		}
	} else {
		for {
			// Read files to check for user supplied server.key and cert.pem
			NewServerKey := CheckCerts("server.key")
			NewServerCert := CheckCerts("cert.pem")

			// If return value is not empty then use that for TLS server
			if NewServerKey != "" && NewServerCert != "" {
				color.Blue("[+] Starting encrypted listener with cert files on %s", listenAddr)
				StartTLSServer(protocol, NewServerKey, NewServerCert, listenAddr, program)
			} else {
				// Use the hardcoded certs
				color.Blue("[+] Starting encrypted listener with hardcoded certs on %s", listenAddr)
				StartTLSServer(protocol, serverKey, serverCert, listenAddr, program)
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
	flag.BoolVar(&encrypted, "x", false, "Use TLS encryption.  Either hardcoded or use cert files")
	flag.BoolVar(&listen, "l", false, "Listen mode")
	flag.BoolVar(&noresolve, "n", false, "Do not resolve domain")
	flag.BoolVar(&nodata, "z", false, "Do not send any data")
	flag.BoolVar(&ver4, "4", false, "Force IPv4")
	flag.BoolVar(&ver6, "6", false, "Force IPv6")

	flag.Parse()

	// End flag parser

	// If no arguments then display help
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		fmt.Println("netgopha [-l] [-e] [-p listen port ] [-s listen ip address] [ip/hostname] [port]")
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
