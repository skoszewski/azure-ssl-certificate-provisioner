package utilities

import "runtime"

// GetDefaultShell returns the default shell based on the operating system
func GetDefaultShell() string {
	switch runtime.GOOS {
	case "windows":
		return "powershell"
	case "linux", "darwin":
		return "bash"
	default:
		return "bash" // Default to bash for unknown OS
	}
}
