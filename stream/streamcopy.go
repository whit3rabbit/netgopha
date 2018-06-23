package stream

import (
	"io"
	"net"

	"github.com/fatih/color"
)

// streamCopy is the sync between OS and stream
// https://github.com/vfedoroff/go-netcat/blob/master/main.go
func StreamCopy(src io.Reader, dst io.Writer) <-chan int {

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
