package types

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// AcmeUser implements the ACME user interface for lego client
type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}

func (u *AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *AcmeUser) SetPrivateKey(key crypto.PrivateKey) {
	u.key = key
}

func (u *AcmeUser) SetRegistration(reg *registration.Resource) {
	u.Registration = reg
}

// Account represents the lego-compatible account structure for persistence
type Account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey      // Not serialized to JSON
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

func (a *Account) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

func (a *Account) SetPrivateKey(key crypto.PrivateKey) {
	a.key = key
}

// ServicePrincipalInfo contains Azure service principal information
type ServicePrincipalInfo struct {
	ApplicationID      string
	ClientID           string
	ClientSecret       string
	ServicePrincipalID string
	SubscriptionID     string
	TenantID           string
	UseCertAuth        bool
	PrivateKeyPath     string
	CertificatePath    string
}
