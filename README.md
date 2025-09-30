# Azure SSL Certificate Provisioner

Automatically provision SSL certificates from Let's Encrypt for Azure DNS zones. This tool scans Azure DNS zones for records marked with ACME metadata and automatically provisions SSL certificates using Let's Encrypt, storing them in Azure Key Vault.

## Disclaimer

**This code has been mostly generated with AI assistance. Use at your own risk.**

The code has been reviewed and is available under the MIT license.

## Features

- **Automatic SSL Certificate Provisioning** - Obtains certificates from Let's Encrypt using DNS-01 challenges
- **Metadata-Driven Discovery** - Only processes DNS records marked with `acme=true` metadata
- **Azure Integration** - Works with Azure DNS zones and stores certificates in Azure Key Vault
- **Certificate Renewal** - Automatically renews certificates expiring within configurable threshold (default: 7 days)
- **Staging Support** - Built-in support for Let's Encrypt staging environment for testing
- **Template Generation** - Generate environment variable templates for easy setup
- **Lego Compatibility** - Full compatibility with [go-acme/lego](https://github.com/go-acme/lego) account storage format
- **Service Principal Management** - Built-in Azure AD application and service principal creation with role assignments

## Prerequisites

1. **Azure Subscription** with appropriate permissions
2. **Azure DNS Zone** configured and accessible
3. **Azure Key Vault** for certificate storage
4. **Azure Service Principal** with the following permissions:
   - DNS Zone Contributor on target DNS zones
   - Key Vault Certificate Officer on target Key Vault
   - Reader access on resource groups and subscriptions

## Installation

### From Source

```bash
git clone https://github.com/skoszewski/azure-ssl-certificate-provisioner.git
cd azure-ssl-certificate-provisioner/app
go build -o azure-ssl-certificate-provisioner .
```

## Configuration

The Azure SSL Certificate Provisioner supports multiple configuration methods with the following priority order:

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration files**
4. **Default values** (lowest priority)

### Configuration Files

The tool supports loading configuration from files in multiple formats. It looks for a file named `config.*` in the current working directory:

- `config.yaml` or `config.yml` (YAML format) - *Recommended*
- `config.json` (JSON format)
- `config.toml` (TOML format)
- `config.env` (Environment file format)

Use the `config` command to generate templates for any of these formats.

#### Generating Configuration Files

Use the `config` command to generate configuration templates in your preferred format:

```bash
# Generate YAML configuration (default - most user-friendly)
./azure-ssl-certificate-provisioner config > config.yaml

# Generate specific formats
./azure-ssl-certificate-provisioner config yaml > config.yaml
./azure-ssl-certificate-provisioner config json > config.json
./azure-ssl-certificate-provisioner config toml > config.toml

# For environment variables, use the environment command instead
./azure-ssl-certificate-provisioner environment bash > .env
```

**YAML Configuration Example (`config.yaml`):**
```yaml
# Azure Configuration
subscription: "your-azure-subscription-id"
resource-group: "your-resource-group-name"
key-vault-url: "https://your-keyvault.vault.azure.net/"

# ACME Configuration
email: "your-email@example.com"
staging: true
expire-threshold: 7

# Azure Authentication (Service Principal)
azure-client-id: "your-service-principal-client-id"
azure-client-secret: "your-service-principal-client-secret"
azure-tenant-id: "your-azure-tenant-id"

# DNS Zones (optional)
zones:
  - "example.com"
  - "subdomain.example.com"
```

**JSON Configuration Example (`config.json`):**
```json
{
  "subscription": "your-azure-subscription-id",
  "resource-group": "your-resource-group-name",
  "key-vault-url": "https://your-keyvault.vault.azure.net/",
  "email": "your-email@example.com",
  "staging": true,
  "expire-threshold": 7,
  "azure-client-id": "your-service-principal-client-id",
  "azure-client-secret": "your-service-principal-client-secret",
  "azure-tenant-id": "your-azure-tenant-id",
  "zones": ["example.com", "subdomain.example.com"]
}
```

**TOML Configuration Example (`config.toml`):**
```toml
# Azure Configuration
subscription = "your-azure-subscription-id"
resource-group = "your-resource-group-name"
key-vault-url = "https://your-keyvault.vault.azure.net/"

# ACME Configuration
email = "your-email@example.com"
staging = true
expire-threshold = 7

# Azure Authentication (Service Principal)
azure-client-id = "your-service-principal-client-id"
azure-client-secret = "your-service-principal-client-secret"
azure-tenant-id = "your-azure-tenant-id"

# DNS Zones (optional)
zones = ["example.com", "subdomain.example.com"]
```

### ACME Account Storage

The tool uses **lego-compatible account storage** in `~/.lego/accounts/`. This means:
- **Existing lego users**: Your accounts work immediately, no migration needed
- **New users**: Accounts created here work with the original lego command
- **Seamless switching**: Use either tool with the same accounts

### Service Principal Setup

Before using the certificate provisioner, you need to create an Azure service principal with the necessary permissions. You can use the built-in command to create one:

```bash
# Create service principal with DNS Zone Contributor role
./azure-ssl-certificate-provisioner create-service-principal \
  --name "SSL Certificate Provisioner" \
  --assign-dns-role \
  --resource-group "your-dns-resource-group"
```

This command will:
1. Create an Azure AD application
2. Create a service principal for the application  
3. Generate a client secret
4. Optionally assign DNS Zone Contributor role to the specified resource group
5. Output environment variables in your preferred shell format

**Required Azure Permissions:**
- **Application Developer** or **Global Administrator** role to create Azure AD applications
- **Owner** or **User Access Administrator** role on the target resource group (for DNS role assignment)

### Environment Variables

The tool requires the following environment variables:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `LEGO_EMAIL` | ✅ | Email address for ACME account registration | `your-email@example.com` |
| `AZURE_SUBSCRIPTION_ID` | ✅ | Azure subscription ID | `12345678-1234-1234-1234-123456789012` |
| `AZURE_RESOURCE_GROUP` | ✅ | Resource group containing DNS zones | `my-dns-rg` |
| `AZURE_KEY_VAULT_URL` | ✅ | Key Vault URL for certificate storage | `https://my-vault.vault.azure.net/` |
| `AZURE_AUTH_METHOD` | ❌ | Authentication method (`msi`, `cli`, etc.) | `msi` |
| `AZURE_CLIENT_ID` | ⚠️ | Service Principal/User-assigned MSI client ID | `87654321-4321-4321-4321-210987654321` |
| `AZURE_CLIENT_SECRET` | ⚠️ | Service Principal client secret | `your-secret-key` |
| `AZURE_TENANT_ID` | ⚠️ | Azure tenant ID | `11111111-2222-3333-4444-555555555555` |

**Legend:**
- ✅ **Always Required**: Must be set in all configurations
- ⚠️ **Conditionally Required**: Required for Service Principal authentication, optional for MSI
- ❌ **Optional**: Used to specify authentication method explicitly

### Generate Environment Template

Use the `environment` command to generate environment variable templates:

```bash
# Generate Bash template (default)
./azure-ssl-certificate-provisioner environment

# Generate PowerShell template
./azure-ssl-certificate-provisioner environment --shell powershell
```

**Example Bash Output:**
```bash
# Azure SSL Certificate Provisioner - Environment Variables
export LEGO_EMAIL="your-email@example.com"
export AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
export AZURE_RESOURCE_GROUP="your-resource-group-name"
export AZURE_KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
export AZURE_CLIENT_ID="your-service-principal-client-id"
export AZURE_CLIENT_SECRET="your-service-principal-client-secret"
export AZURE_TENANT_ID="your-azure-tenant-id"
```

### Authentication Methods

The tool supports multiple Azure authentication methods for maximum flexibility:

#### 1. Service Principal (Traditional)
Uses explicit service principal credentials:
```bash
export AZURE_CLIENT_ID="your-service-principal-client-id"
export AZURE_CLIENT_SECRET="your-service-principal-client-secret"
export AZURE_TENANT_ID="your-azure-tenant-id"
```

#### 2. Managed Identity (Recommended for Azure Resources)
Use Azure Managed Identity for secure, credential-free authentication:

**System-Assigned Managed Identity:**
```bash
export AZURE_AUTH_METHOD=msi
# No client credentials needed - automatically detected
```

**User-Assigned Managed Identity:**
```bash
export AZURE_AUTH_METHOD=msi
export AZURE_CLIENT_ID="your-user-assigned-msi-client-id"
```

**Azure Arc Managed Identity:**
```bash
export AZURE_AUTH_METHOD=msi
export IMDS_ENDPOINT=http://localhost:40342
export IDENTITY_ENDPOINT=http://localhost:40342/metadata/identity/oauth2/token
```

#### 3. Azure CLI
Use Azure CLI authentication (great for local development):
```bash
export AZURE_AUTH_METHOD=cli
# Run 'az login' first
```

#### 4. Default Credential Chain
Let Azure SDK automatically detect the best authentication method:
```bash
# Leave AZURE_AUTH_METHOD unset - tries MSI, CLI, etc. automatically
```

#### Additional Authentication Options
- `AZURE_AUTH_MSI_TIMEOUT`: MSI timeout duration (default: 2s)
- `AZURE_USE_MSI=true`: Legacy support (automatically converts to `AZURE_AUTH_METHOD=msi`)

### Lego Compatibility

This tool uses the same environment variable names as the [lego](https://github.com/go-acme/lego) command-line tool for maximum compatibility:

- **Email**: `LEGO_EMAIL` (compatible with lego's `--email` flag and environment variable)
- **Account Storage**: Uses lego-compatible account storage in `~/.lego/accounts/`
- **Environment Variables**: Follows lego's naming conventions where applicable
- **Azure DNS Provider**: Uses lego's modern `azuredns` provider with full MSI support

This ensures seamless integration with existing lego-based workflows and tooling.

## Usage

### DNS Record Setup

Before running the certificate provisioner, mark your DNS records with ACME metadata:

```bash
# Add metadata to enable certificate provisioning for a DNS record
az network dns record-set a update \
  --resource-group "my-dns-rg" \
  --zone-name "example.com" \
  --name "www" \
  --metadata acme=true

# For wildcard certificates, mark the zone apex
az network dns record-set a update \
  --resource-group "my-dns-rg" \
  --zone-name "example.com" \
  --name "@" \
  --metadata acme=true
```

### Running the Certificate Provisioner

#### Basic Usage

```bash
# Run with staging environment (recommended for testing) - scan all zones
./azure-ssl-certificate-provisioner run \
  --email "your-email@example.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg" \
  --staging

# Run with production Let's Encrypt (for live certificates) - specific zone
./azure-ssl-certificate-provisioner run \
  --zones example.com \
  --email "your-email@example.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg" \
  --staging=false
```

#### Multiple Zones

```bash
./azure-ssl-certificate-provisioner run \
  -z example.com \
  -z api.example.com \
  -z "staging.example.com" \
  -e "your-email@example.com" \
  -s "12345678-1234-1234-1234-123456789012" \
  -g "my-dns-rg"
```

#### Using Environment Variables

```bash
# Set environment variables
export LEGO_EMAIL="your-email@example.com"
export AZURE_SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
export AZURE_RESOURCE_GROUP="my-dns-rg"
export AZURE_KEY_VAULT_URL="https://my-vault.vault.azure.net/"
export AZURE_CLIENT_ID="87654321-4321-4321-4321-210987654321"
export AZURE_CLIENT_SECRET="your-secret-key"
export AZURE_TENANT_ID="11111111-2222-3333-4444-555555555555"

# Run the provisioner (scan all zones in resource group)
./azure-ssl-certificate-provisioner run

# Or run for specific zones
./azure-ssl-certificate-provisioner run --zones example.com
```

### Command Reference

#### Global Commands

```bash
# Show help
./azure-ssl-certificate-provisioner --help

# Show version and available commands
./azure-ssl-certificate-provisioner
```

#### `run` Command

Executes the SSL certificate provisioner.

```bash
./azure-ssl-certificate-provisioner run [flags]

Flags:
  -z, --zones strings           DNS zone(s) to search for records. If omitted, all zones in the resource group will be scanned
  -e, --email string            Email address for ACME account registration (required)
  -t, --expire-threshold int    Certificate expiration threshold in days (default: 7)
  -g, --resource-group string   Azure resource group name (required)
  -s, --subscription string     Azure subscription ID (required)
      --staging                 Use Let's Encrypt staging environment (default: true)
  -h, --help                    Help for run
```

#### `list` Command

Lists DNS records and their certificate status without provisioning certificates.

```bash
./azure-ssl-certificate-provisioner list [flags]

Flags:
  -z, --zones strings           DNS zone(s) to search for records. If omitted, all zones in the resource group will be scanned
  -e, --email string            Email address for ACME account registration (used for certificate lookup)
  -t, --expire-threshold int    Certificate expiration threshold in days (default: 7)
  -g, --resource-group string   Azure resource group name (required)
  -s, --subscription string     Azure subscription ID (required)
      --staging                 Use Let's Encrypt staging environment (default: true)
  -h, --help                    Help for list
```

**Usage Examples:**

```bash
# List all certificates and their status
./azure-ssl-certificate-provisioner list \
  --email "your-email@example.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg"

# List certificates for specific zones
./azure-ssl-certificate-provisioner list \
  --zones example.com \
  --zones api.example.com \
  --email "your-email@example.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg"

# Check certificates with custom expiration threshold
./azure-ssl-certificate-provisioner list \
  --expire-threshold 30 \
  --email "your-email@example.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg"
```

#### `environment` Command

Generates environment variable templates.

```bash
./azure-ssl-certificate-provisioner environment [command]

Available Commands:
  bash        Generate Bash environment variable template
  powershell  Generate PowerShell environment variable template

Flags:
  -h, --help   Help for environment
```

**Usage Examples:**

```bash
# Generate Bash template
./azure-ssl-certificate-provisioner environment bash

# Generate PowerShell template
./azure-ssl-certificate-provisioner environment powershell
```

#### `config` Command

Generates configuration file templates in different formats.

```bash
./azure-ssl-certificate-provisioner config [format]

Supported formats: json, toml, yaml (default: yaml)
For environment variables, use: azure-ssl-certificate-provisioner environment

Flags:
  -h, --help   help for config
```

**Usage Examples:**

```bash
# Generate YAML configuration template (default)
./azure-ssl-certificate-provisioner config

# Generate specific format templates
./azure-ssl-certificate-provisioner config yaml
./azure-ssl-certificate-provisioner config json
./azure-ssl-certificate-provisioner config toml

# Generate configuration and save to file
./azure-ssl-certificate-provisioner config > config.yaml
./azure-ssl-certificate-provisioner config json > config.json
```

#### `create-sp` Command


Creates an Azure AD application and service principal for SSL certificate provisioning.

Note: You must specify both the tenant ID and subscription ID to ensure the service principal
is created in the correct Azure environment.

```bash
./azure-ssl-certificate-provisioner create-sp [flags]

Flags:
  -n, --name string                Display name for the Azure AD application (required)
  -t, --tenant-id string           Azure tenant ID (required)
  -s, --subscription-id string     Azure subscription ID (required)
      --assign-dns-role            Assign DNS Zone Contributor role to the specified resource group
  -g, --resource-group string      Resource group name for DNS Zone Contributor role assignment
      --kv-name string             Key Vault name for Certificates Officer role assignment
      --kv-resource-group string   Resource group name for the Key Vault
      --shell string               Shell type for output template (bash, powershell) (default: "bash")
  -h, --help                       Help for create-sp
```

**Usage Examples:**

```bash
# Create service principal without role assignment
./azure-ssl-certificate-provisioner create-sp \
  --name "SSL Certificate Provisioner"

# Create service principal and assign DNS Zone Contributor role
# Create a service principal for Certificate Provisioner
azure-ssl-certificate-provisioner create-sp \
  --name "certificate-provisioner-app" \
  --tenant-id "12345678-1234-1234-1234-123456789012" \
  --subscription-id "87654321-4321-4321-4321-210987654321"

# Create a service principal and assign DNS Zone Contributor role
azure-ssl-certificate-provisioner create-sp \
  --name "certificate-provisioner-app" \
  --tenant-id "12345678-1234-1234-1234-123456789012" \
  --subscription-id "87654321-4321-4321-4321-210987654321" \
  --assign-dns-role \
  --resource-group "dns-rg"

# Generate PowerShell template
azure-ssl-certificate-provisioner create-sp \
  --name "certificate-provisioner-app" \
  --tenant-id "12345678-1234-1234-1234-123456789012" \
  --subscription-id "87654321-4321-4321-4321-210987654321" \
  --shell "powershell"

# Generate PowerShell output format
./azure-ssl-certificate-provisioner create-sp \
  --name "SSL Certificate Provisioner" \
  --shell powershell
```

## Lego Compatibility

This tool is **fully compatible** with the [go-acme/lego](https://github.com/go-acme/lego) ACME client. This means:

### **Account Interoperability**
- **Reuse existing lego accounts**: If you already have lego accounts, they work directly with azure-ssl-certificate-provisioner
- **Cross-tool compatibility**: Accounts created by azure-ssl-certificate-provisioner can be used by the lego command
- **Standard format**: Uses the same directory structure and file formats as lego

### **Directory Structure**
Both tools use the same account storage format:
```
~/.lego/accounts/
├── acme-v02.api.letsencrypt.org_443/              # Production Let's Encrypt
│   └── your-email@example.com/
│       ├── account.json                           # Account registration data
│       └── keys/
│           └── your-email@example.com.key         # RSA private key (PEM)
└── acme-staging-v02.api.letsencrypt.org_443/      # Staging Let's Encrypt  
    └── your-email@example.com/
        ├── account.json
        └── keys/
            └── your-email@example.com.key
```

### **Migration Benefits**
- **From lego**: Works immediately with existing lego accounts (no migration needed)
- **To lego**: Switch between tools seamlessly for different use cases
- **Backup compatibility**: Standard format makes backups portable between tools

## How It Works

1. **Discovery**: Scans specified Azure DNS zones for A and CNAME records
2. **Filtering**: Only processes records with `acme=true` metadata
3. **Account Management**: Uses lego-compatible account storage in `~/.lego/accounts/`
4. **Certificate Check**: Checks existing certificates in Key Vault for expiration
5. **Renewal Logic**: Renews certificates expiring within the specified threshold (default: 7 days)
6. **ACME Challenge**: Uses DNS-01 challenge with Azure DNS provider
7. **Storage**: Stores certificates in PKCS#12 format in Azure Key Vault

## Certificate Lifecycle

- **Account Management**: Uses lego-compatible ACME account storage in `~/.lego/accounts/`
- **New Certificates**: Generated for domains without existing certificates
- **Renewal**: Automatic renewal for certificates expiring within the specified threshold (default: 7 days)
- **Validation**: DNS-01 challenge validates domain ownership using Azure DNS
- **Storage**: Certificates stored as secrets in Azure Key Vault with naming pattern: `cert-domain-com`
- **Cross-tool compatibility**: ACME accounts work with both azure-ssl-certificate-provisioner and lego

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify all environment variables are set correctly
   - Ensure Service Principal has appropriate permissions
   - Check Azure tenant and subscription IDs

2. **DNS Provider Initialization Failed**
   - Verify Azure credentials have DNS Zone Contributor permissions
   - Ensure the specified resource group and DNS zones exist
   - Check network connectivity to Azure services

3. **Certificate Import Failures**
   - Verify Key Vault permissions (Certificate Officer role required)
   - Ensure Key Vault URL is correctly formatted
   - Check Key Vault access policies

4. **Certificates Not Being Renewed**
   - Check the expiration threshold setting (default: 7 days)
   - Use `--expire-threshold` to adjust renewal timing
   - Verify certificate expiration dates in Key Vault logs

5. **Account Compatibility Issues**
   - Existing lego accounts should work immediately
   - Check account permissions in `~/.lego/accounts/` directory (should be 0600)
   - Verify email matches between different tool invocations
   - For staging vs production, accounts are stored in separate directories

### Debug Mode

For detailed logging, check the application output. The tool provides comprehensive logging for:
- Authentication status
- DNS zone discovery
- Certificate expiration checks
- ACME challenge progress
- Certificate import results

## Security Considerations

- **Environment Variables**: Store sensitive values securely, never commit secrets to version control
- **Service Principal**: Use minimal required permissions following principle of least privilege
- **Key Vault**: Enable audit logging and access policies for certificate access
- **Staging First**: Always test with Let's Encrypt staging before using production

## Production Deployment

### Recommended Setup

1. **Use Azure Managed Identity** when running on Azure VMs/Container Instances
2. **Set up monitoring** for certificate expiration and renewal failures
3. **Configure alerts** for failed certificate provisioning
4. **Schedule regular runs** via cron jobs or Azure Logic Apps
5. **Use production Let's Encrypt** only after successful staging tests

### Example Cron Job

```bash
# Run certificate provisioner daily at 2 AM (scan all zones)
0 2 * * * /path/to/azure-ssl-certificate-provisioner run --staging=false
```

## Lego Integration Examples

### Using Existing Lego Accounts

If you already have lego accounts, they work immediately:

```bash
# Check existing lego accounts
ls -la ~/.lego/accounts/

# Use with azure-ssl-certificate-provisioner (same email as lego account)
./azure-ssl-certificate-provisioner run \
  --zones example.com \
  --email "same-email@used-with-lego.com" \
  --subscription "12345678-1234-1234-1234-123456789012" \
  --resource-group "my-dns-rg"
```

### Sharing Accounts Between Tools

Create account with azure-ssl-certificate-provisioner, then use with lego:

```bash
# 1. Create account with azure-ssl-certificate-provisioner
./azure-ssl-certificate-provisioner run --zones example.com --email test@example.com --staging

# 2. Use the same account with lego (install lego separately)
lego --email test@example.com --dns azure --domains example.com --server https://acme-staging-v02.api.letsencrypt.org/directory run

# 3. Both tools share the same account in ~/.lego/accounts/
```

### Migration from Legacy Storage

The tool automatically uses the new lego-compatible format. Previous single-file storage is deprecated but existing functionality is preserved.

## References

- **Let's Encrypt Staging**: [https://acme-staging-v02.api.letsencrypt.org/directory](https://acme-staging-v02.api.letsencrypt.org/directory)
- **Let's Encrypt Production**: [https://acme-v02.api.letsencrypt.org/directory](https://acme-v02.api.letsencrypt.org/directory)
- **Azure DNS Documentation**: [Azure DNS Overview](https://docs.microsoft.com/en-us/azure/dns/)
- **Azure Key Vault Documentation**: [Key Vault Certificates](https://docs.microsoft.com/en-us/azure/key-vault/certificates/)
- **Lego ACME Client**: [go-acme/lego](https://github.com/go-acme/lego)
- **Lego Documentation**: [Lego User Guide](https://go-acme.github.io/lego/)

---

## License

This project is licensed under the MIT License. The code was primarily generated using AI assistance. Use at your own risk.
