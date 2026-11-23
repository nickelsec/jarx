package proc

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tree is the job object the server runs in. Everything it starts lands in
// the job too, and closing the job kills them all.
type tree struct{ job windows.Handle }

// startTree starts the server suspended, puts it in a job that kills the
// whole tree when closed, and only then lets it run, so nothing it starts
// can get out of the job first (golang/go#79927). The job handle isn't
// inheritable.
func startTree(cmd *exec.Cmd) (*tree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	//nolint:gosec // G103: the documented way to pass the struct
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("set job limits: %w", err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("start: %w", err)
	}
	pid := uint32(cmd.Process.Pid) //nolint:gosec // G115: a Windows pid fits
	if err := assign(job, pid); err != nil {
		_ = cmd.Process.Kill() // still suspended, so it never ran
		_ = windows.CloseHandle(job)
		return nil, err
	}
	return &tree{job: job}, nil
}

// assign puts the suspended process in the job, then resumes it.
func assign(job windows.Handle, pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	err = windows.AssignProcessToJobObject(job, h)
	_ = windows.CloseHandle(h)
	if err != nil {
		return fmt.Errorf("assign to job: %w", err)
	}
	return resume(pid)
}

// resume resumes a suspended process's threads: its one main thread, found
// with a Toolhelp32 snapshot, since a suspended process can't start more.
// These calls are documented, unlike ntdll's NtResumeProcess.
func resume(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	te := windows.ThreadEntry32{}
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		if rerr := resumeThread(te.ThreadID); rerr != nil {
			return rerr
		}
		resumed++
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("walk threads: %w", err)
	}
	if resumed == 0 {
		return errors.New("no thread to resume")
	}
	return nil
}

func resumeThread(id uint32) error {
	th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, id)
	if err != nil {
		return fmt.Errorf("open thread: %w", err)
	}
	_, err = windows.ResumeThread(th)
	_ = windows.CloseHandle(th)
	if err != nil {
		return fmt.Errorf("resume thread: %w", err)
	}
	return nil
}

// kill ends every process in the job and closes it.
func (t *tree) kill() error {
	err := windows.TerminateJobObject(t.job, 1)
	_ = windows.CloseHandle(t.job)
	if err != nil {
		return fmt.Errorf("terminate job: %w", err)
	}
	return nil
}
