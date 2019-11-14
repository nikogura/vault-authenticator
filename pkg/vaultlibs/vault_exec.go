package vaultlibs

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Exec runs the provided shell command with secrets from the path given exported into it's environment.
func Exec(args []string, data map[string]interface{}, clean bool) (err error) {
	command := args[0]

	// command could be a quoted string.  If so, split it apart and reconstruct the args
	parsedArgs := strings.Split(command, " ")
	if len(parsedArgs) > 0 {
		command = parsedArgs[0]
		oldArgs := args[1:]

		args = parsedArgs
		args = append(args, oldArgs...)
	}

	cmdPath, err := exec.LookPath(command)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Couldn't find command %q in path.", command))
	}

	var execEnv []string

	if clean {
		execEnv = make([]string, 0)
	} else {
		execEnv = os.Environ()
	}

	for key, value := range data {
		// simple append is fine, the shell will ensure the last one wins in case of duplicates
		execEnv = append(execEnv, fmt.Sprintf("%s=%s", key, value))
	}

	err = syscall.Exec(cmdPath, args, execEnv)
	if err != nil {
		fmt.Printf("Error calling %q: %s", command, err)
		os.Exit(1)
	}

	return err
}
