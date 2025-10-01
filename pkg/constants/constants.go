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
	Name         = "name"
	ClientID     = "client-id"
	KeyVaultName = "kv-name"
	KeyVaultRG   = "kv-resource-group"
	NoRoles      = "no-roles"
	UseCertAuth  = "use-cert-auth"
	KeyFileName  = "key-file-name"
	CertFileName = "cert-file-name"

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
	EnvAzureClientId       = "AZURE_CLIENT_ID"
	EnvAzureClientSecret   = "AZURE_CLIENT_SECRET"
	EnvAzureTenantId       = "AZURE_TENANT_ID"
	EnvAzureSubscriptionId = "AZURE_SUBSCRIPTION_ID"
	EnvResourceGroup       = "AZURE_RESOURCE_GROUP"
	EnvAzureKeyVaultURL    = "AZURE_KEY_VAULT_URL"
	EnvLegoEmail           = "LEGO_EMAIL"
	EnvConfigFile          = "CONFIG_FILE"
)
