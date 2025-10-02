package utilities

import (
	"log"
)

// Verbose holds the global verbose flag
var Verbose bool = false

func GetVerbosePtr() *bool {
	return &Verbose
}

func SetVerbose(v bool) {
	Verbose = v
}

func LogDefault(format string, args ...any) {
	log.Printf(format, args...)
}

func LogWarning(format string, args ...any) {
	log.Printf("Warning: "+format, args...)
}

func LogError(format string, args ...any) {
	log.Printf("Error: "+format, args...)
}

func LogFatal(format string, args ...any) {
	log.Fatalf("Fatal: "+format, args...)
}

// LogVerbose logs a message only if verbose flag is set
func LogVerbose(format string, args ...any) {
	if Verbose {
		log.Printf(format, args...)
	}
}
