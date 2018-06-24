package stream

import (
	"net"
	"os"

	"github.com/fatih/color"
)

// TCPConnHandle = TCP -> Stdout and Stdin -> TCP
// https://github.com/vfedoroff/go-netcat/blob/master/main.go
func TCPConnHandle(con net.Conn, nodata bool) {

	if !nodata {
		// Remote -> Client
		chanToStdout := StreamCopy(con, os.Stdout)
		// Client -> Remote
		chanToRemote := StreamCopy(os.Stdin, con)
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
		chanToStdout := StreamCopy(con, os.Stdout)
		select {
		case <-chanToStdout:
			color.Red("[!] Remote connection is closed")
			con.Close()
			os.Exit(1)
		}
	}
}
