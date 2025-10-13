import azure.functions as func
import logging
import os
from provisioner import Provisioner

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.ERROR)

@app.route(route="provision")
def provision(req: func.HttpRequest) -> func.HttpResponse:
    # Let's create a Provisioner instance and run it
    logging.info('Azure SSL Certificate Provisioner function.')

    dry_run = req.params.get('dry_run', 'false').lower() == 'true'

    try:
        provisioner = Provisioner(os.environ, dry_run=dry_run)
    except ValueError as e:
        logging.error("Error initializing Provisioner: %s", e)
        return func.HttpResponse(
            "Error initializing Provisioner.",
            status_code=500
        )

    if provisioner.dry_run:
        logging.info("Dry run enabled; no changes will be made.")
    else:
        provisioner.prepare_acme_client()

    results, failures, zones_found = provisioner.process_zones()

    if not zones_found:
        return func.HttpResponse(
            "No zones found to process.",
            status_code=200
        )

    if failures:
        logging.error("Provisioning completed with %d failure(s)", failures)
        return func.HttpResponse(
            f"Provisioning completed with {failures} failure(s).",
            status_code=500
        )

    if not results:
        logging.info("No certificates created or renewed; all eligible records are up to date.")

    return func.HttpResponse(
        "I have run the provisioner successfully.",
        status_code=200
    )
