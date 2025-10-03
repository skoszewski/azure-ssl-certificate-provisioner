package types

import (
	"azure-ssl-certificate-provisioner/pkg/constants"
)

// ServicePrincipalInfo contains Azure service principal information
type ServicePrincipalInfo struct {
	TenantID           string
	ClientID           string
	ClientSecret       string
	UseCertAuth        bool
	PrivateKeyPath     string
	CertificatePath    string
	ApplicationID      string
	ServicePrincipalID string
}

func (sp *ServicePrincipalInfo) GetValue(key string) string {
	switch key {
	case constants.TenantID:
		return sp.TenantID
	case constants.AzureClientID:
		return sp.ClientID
	case constants.AzureClientSecret:
		return sp.ClientSecret
	case constants.PrivateKeyPath:
		return sp.PrivateKeyPath
	case constants.CertificatePath:
		return sp.CertificatePath
	default:
		// return an empty string for unknown keys
		return ""
	}
}
