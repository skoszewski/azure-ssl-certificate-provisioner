package constants

const (
	// Provisioning related keywords and Viper keys
	SubscriptionID    = "subscription-id"
	TenantID          = "tenant-id"
	Zones             = "zones"
	ResourceGroupName = "resource-group"
	KeyVaultURL       = "key-vault-url"
	Email             = "email"
	ConfigFile        = "config"

	// Authentication related keywords and Viper keys
	AzureClientID       = "azure-client-id"
	AzureClientSecret   = "azure-client-secret"
	AzureTenantID       = "azure-tenant-id"
	AzureAuthMethod     = "azure-auth-method"
	AzureAuthMsiTimeout = "azure-auth-msi-timeout"

	// Keys related to Service Principal creation and management
	Name            = "name"
	ClientID        = "client-id"
	KeyVaultName    = "kv-name"
	KeyVaultRG      = "kv-resource-group"
	DryRun          = "dry-run"
	UseCertAuth     = "use-cert-auth"
	PrivateKeyPath  = "private-key-path"
	CertificatePath = "certificate-path"

	// Other keywords and Viper keys
	Staging         = "staging"
	ExpireThreshold = "expire-threshold"
	Format          = "format"
	Verbose         = "verbose"
	Shell           = "shell"
	UseMSI          = "use-msi"
	MSISystem       = "system"
	MSIUser         = "user"
	Bash            = "bash"
	PowerShell      = "powershell"
	JSON            = "json"
	YAML            = "yaml"
	TOML            = "toml"
	CommandName     = "azure-ssl-certificate-provisioner"

	// Environment variable names
	EnvResourceGroup = "RESOURCE_GROUP"
	EnvKeyVaultURL   = "KEY_VAULT_URL"
	EnvLegoEmail     = "LEGO_EMAIL"
	EnvConfigFile    = "CONFIG_FILE"
)
