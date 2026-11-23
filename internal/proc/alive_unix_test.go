//go:build !windows

package proc

import "syscall"

// alive says whether pid is still running.
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }
