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
	AzureClientId        = "azure-client-id"
	AzureSubscriptionId  = "azure-subscription-id"
	AzureTenantId        = "azure-tenant-id"
	AzureClientSecret    = "azure-client-secret"
	AzureKeyFileName     = "azure-key-file-name"
	AzureCertFileName    = "azure-cert-file-name"
	AzureAuthMethod      = "azure-auth-method"
	AzureAuthMsiTimeout  = "azure-auth-msi-timeout"
	AzureKeyVaultName    = "azure-key-vault-name"
	AzureKVResourceGroup = "azure-kv-resource-group"

	// Other keywords and Viper keys
	Staging         = "staging"
	ExpireThreshold = "expire-threshold"
	Format          = "format"
	Verbose         = "verbose"
	Shell           = "shell"
	UseMSI          = "use-msi"
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
	EnvAzureKeyVaultURL    = "AZURE_KEY_VAULT_URL"
	EnvLegoEmail           = "LEGO_EMAIL"
	EnvConfigFile          = "CONFIG_FILE"
)
