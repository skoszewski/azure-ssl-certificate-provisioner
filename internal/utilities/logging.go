package utilities

import "log"

// Verbose holds the global verbose flag
var Verbose bool = false

// SetVerbose sets the global verbose flag
func SetVerbose(verbose bool) {
	Verbose = verbose
}

// LogDefault logs a message always (replaces current log.Printf calls)
func LogDefault(format string, args ...any) {
	log.Printf(format, args...)
}

// LogVerbose logs a message only if verbose flag is set
func LogVerbose(format string, args ...any) {
	if Verbose {
		log.Printf(format, args...)
	}
}
