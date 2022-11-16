package main

import (
	"fmt"
	"os"

	"github.com/bottlepay/lndsigner"
	"github.com/jessevdk/go-flags"
)

func main() {
	// Load the configuration, and parse any command line options. This
	// function will also set up logging properly.
	loadedConfig, err := lndsigner.LoadConfig()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	// Call the "real" main in a nested manner so the defers will properly
	// be executed in the case of a graceful shutdown.
	if err = lndsigner.Main(
		loadedConfig, lndsigner.ListenerCfg{},
	); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
