# Azure Container App Job

A Container App Job can be used to run a containerized Certificate Provisioner on a schedule or as a one-off task. This is useful for automating the process of obtaining and renewing SSL certificates.

The Terraform configuration in this directory sets up an Azure Container App Job with the necessary environment variables. Authentication is handled via a Managed Identity assigned to the Container App Job. No sensitive information is stored in the configuration.
