package main

import (
	"errors"
	"os"

	"github.com/The-17/agentsecrets/cmd/agentsecrets/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		// Honor an explicit exit code request (env child code, exec protocol);
		// fall back to 1 for any other error.
		var ee *commands.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		os.Exit(1)
	}
}
