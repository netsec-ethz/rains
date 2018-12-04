// package runner provides an interface for running and monitoring services.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner provides a wrapper to run processes in the test framework.
type Runner struct {
	binPath    string
	args       []string
	pwd        string
	cmd        *exec.Cmd
	p          *os.Process
	stdout     *bytes.Buffer
	stderr     *bytes.Buffer
	exitNotify *chan *Runner // Send pointer to this struct on exit.
	ExitErr    error         // Error returned from the process on exit.
	Running    bool
}

// New creates a Runner instance. exitNotify is a channel to which a pointer
// to the runner struct will be sent when the process exits.
func New(binary string, args []string, pwd string, exitNotify *chan *Runner) *Runner {
	r := &Runner{
		binPath:    binary,
		args:       args,
		pwd:        pwd,
		stdout:     bytes.NewBuffer(make([]byte, 0)),
		stderr:     bytes.NewBuffer(make([]byte, 0)),
		exitNotify: exitNotify,
	}
	return r
}

func (r *Runner) Command() string {
	sb := strings.Builder{}
	sb.WriteString(r.binPath)
	for _, arg := range r.args {
		sb.WriteString(" ")
		sb.WriteString(arg)
	}
	return sb.String()
}

func (r *Runner) Stdout() string {
	return r.stdout.String()
}

func (r *Runner) Stderr() string {
	return r.stderr.String()
}

func (r *Runner) Execute(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.binPath, r.args...)
	cmd.Stdout = r.stdout
	cmd.Stderr = r.stderr
	r.cmd = cmd
	r.p = cmd.Process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %v", err)
	}
	r.Running = true
	go func() {
		if err := cmd.Wait(); err != nil {
			r.ExitErr = err
		}
		*(r.exitNotify) <- r
		r.Running = false
	}()
	return nil
}
