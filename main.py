#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from typing import List, Optional

from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.dns import DnsManagementClient

from provisioner import (
    ProvisioningResult,
    build_config_from_env,
    create_acme_client,
    ensure_acme_account,
    ensure_registration,
    list_acme_enabled_records,
    list_target_zones,
    get_credential,
    provision_certificate_for_record,
)


def configure_logging() -> logging.Logger:
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)

    logger = logging.getLogger(__name__)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(level)

    provisioner_logger = logging.getLogger("provisioner")
    if not provisioner_logger.handlers:
        provisioner_logger.addHandler(handler)
    provisioner_logger.setLevel(level)
    provisioner_logger.propagate = False

    return logger


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision or renew SSL certificates for Azure DNS records.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the provisioning flow without registering accounts or issuing certificates.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logger = configure_logging()

    try:
        config = build_config_from_env(os.environ, dry_run=args.dry_run)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    if config.dry_run:
        logger.info("Dry run enabled; no changes will be made.")

    credential = get_credential()
    secret_client = SecretClient(vault_url=config.key_vault_url, credential=credential)
    certificate_client = CertificateClient(vault_url=config.key_vault_url, credential=credential)
    dns_client = DnsManagementClient(credential=credential, subscription_id=config.subscription_id)

    acme_client = None
    net = None
    registration = None
    jwk = None

    if not config.dry_run:
        jwk, registration = ensure_acme_account(config, secret_client)
        acme_client, net = create_acme_client(config, jwk, registration)
        registration = ensure_registration(config, secret_client, acme_client, net, registration)

    zones = list_target_zones(config, dns_client)
    if not zones:
        logger.info("No DNS zones found for resource group %s", config.resource_group)
        return 0

    results: List[ProvisioningResult] = []
    failures = 0

    for zone_name in zones:
        records = list_acme_enabled_records(dns_client, config, zone_name)
        if not records:
            logger.info("Zone %s has no ACME-enabled A or CNAME records", zone_name)
            continue
        logger.info("Processing zone %s (%d records)", zone_name, len(records))
        for record in records:
            fqdn = record.fqdn.rstrip(".")
            try:
                result = provision_certificate_for_record(
                    config,
                    acme_client,
                    net,
                    jwk,
                    dns_client,
                    certificate_client,
                    registration,
                    zone_name,
                    record,
                )
                results.append(result)
                logger.info(
                    "%s: %s (%s)",
                    fqdn,
                    result.action.upper(),
                    result.message,
                )
            except Exception as exc:  # pylint: disable=broad-except
                failures += 1
                logger.exception("Failed to process %s in zone %s: %s", fqdn, zone_name, exc)

    if failures:
        logger.error("Provisioning completed with %d failure(s)", failures)
        return 1

    if not results:
        logger.info("No certificates created or renewed; all eligible records are up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
