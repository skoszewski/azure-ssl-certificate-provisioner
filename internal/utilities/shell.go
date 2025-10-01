package utilities

import (
	"runtime"

	"azure-ssl-certificate-provisioner/pkg/constants"
)

// GetDefaultShell returns the default shell based on the operating system
func GetDefaultShell() string {
	switch runtime.GOOS {
	case "windows":
		return constants.PowerShell
	case "linux", "darwin":
		return constants.Bash
	default:
		return constants.Bash // Default to bash for unknown OS
	}
}
