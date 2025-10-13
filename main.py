#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from typing import List, Optional

from provisioner import Config


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
        config = Config(os.environ, dry_run=args.dry_run)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    if config.dry_run:
        logger.info("Dry run enabled; no changes will be made.")

    config.initialize_clients()

    if not config.dry_run:
        config.ensure_acme_account()
        config.create_acme_client()
        config.ensure_registration()

    results, failures, zones_found = config.process_zones()
    if not zones_found:
        return 0

    if failures:
        logger.error("Provisioning completed with %d failure(s)", failures)
        return 1

    if not results:
        logger.info("No certificates created or renewed; all eligible records are up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
