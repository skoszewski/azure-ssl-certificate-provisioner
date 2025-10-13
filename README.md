# Azure SSL Certificate Provisioner

This project automates the provisioning and renewal of SSL certificates for Azure defined DNS records stored in Azure DNS zones.

## Configuration

The main entry point is `main.py`. Set the environment variables below before running it:

- `ACME_EMAIL` (required): Email address to register the ACME account.
- `AZURE_SUBSCRIPTION_ID` (required): Azure subscription that holds the DNS zones and Key Vault.
- `AZURE_RESOURCE_GROUP` (required): Resource group containing the Azure DNS zones.
- `AZURE_KEY_VAULT_URL` (required): URL of the Key Vault used to store ACME account data and certificates.
- `DNS_ZONES` (optional): Comma-separated list of DNS zone names to process; leave unset to manage every zone in the resource group.
- `CERT_EXPIRY_THRESHOLD_DAYS` (optional, default 7): Renew certificates when they expire within this many days.
- `ACME_DIRECTORY_URL` (optional, default `https://acme-v02.api.letsencrypt.org/directory`): ACME directory endpoint to use.
- `LOG_LEVEL` (optional, default `INFO`): Logging level for runtime output.
