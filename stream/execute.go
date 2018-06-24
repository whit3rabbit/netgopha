// +build !windows

package stream

import (
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/fatih/color"
)

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

	chanToStdout := StreamCopy(conn, cmd.Stdout)
	chanToRemote := StreamCopy(cmd.Stdin, conn)

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
