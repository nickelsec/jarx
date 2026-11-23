//go:build !windows

package proc

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// tree is the server's process group. Everything it starts joins the group,
// unless it leaves on purpose with setsid (see Limits in docs/prd.md).
type tree struct{ pgid int }

func startTree(cmd *exec.Cmd) (*tree, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	return &tree{pgid: cmd.Process.Pid}, nil
}

// kill sends SIGKILL to the whole group.
func (t *tree) kill() error {
	err := syscall.Kill(-t.pgid, syscall.SIGKILL)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill group %d: %w", t.pgid, err)
	}
	return nil
}
