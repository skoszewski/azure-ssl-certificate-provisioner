package utilities

import "log"

// Verbose holds the global verbose flag
var Verbose bool = false

func GetVerbosePtr() *bool {
	return &Verbose
}

func SetVerbose(v bool) {
	Verbose = v
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
