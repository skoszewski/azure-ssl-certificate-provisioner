#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from typing import Optional, List

from provisioner import Provisioner


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Provision or renew SSL certificates for Azure DNS records.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the provisioning flow without registering accounts or issuing certificates.",
    )

    args = parser.parse_args(argv)

    # Read log level from environment variable, default to INFO
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()

    # Configure basic console logging
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

    # Set log level for the root logger and specific loggers
    logger = logging.getLogger(__name__)
    logger.setLevel(level_name)
    logging.getLogger("provisioner").setLevel(level_name)

    try:
        provisioner = Provisioner(os.environ, dry_run=args.dry_run)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    if provisioner.dry_run:
        logger.info("Dry run enabled; no changes will be made.")
    else:
        provisioner.prepare_acme_client()

    results, failures, zones_found = provisioner.process_zones()

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
