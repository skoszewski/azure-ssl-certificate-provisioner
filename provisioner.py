from __future__ import annotations

import datetime as _dt
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple
import logging

from acme import challenges, client, messages
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import ChainedTokenCredential, DefaultAzureCredential, EnvironmentCredential, ManagedIdentityCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from josepy.jwk import JWKRSA
import dns.resolver


DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
USER_AGENT = "azure-ssl-certificate-provisioner/1.0"
DEFAULT_DNS_TTL = 60
DEFAULT_PROPAGATION_TIMEOUT = 420
DEFAULT_PROPAGATION_INTERVAL = 6
DEFAULT_ORDER_TIMEOUT = 300

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Config:
    acme_email: str
    subscription_id: str
    resource_group: str
    key_vault_url: str
    cert_expiry_threshold_days: int
    dns_zones: Optional[Sequence[str]]
    acme_directory_url: str
    dns_ttl: int
    propagation_timeout: int
    propagation_interval: int
    order_timeout: int
    dry_run: bool
    _acme_client: Optional[client.ClientV2]
    _net: Optional[client.ClientNetwork]
    _jwk: Optional[JWKRSA]
    _dns_client: Optional[DnsManagementClient]
    _certificate_client: Optional[CertificateClient]
    _secret_client: Optional[SecretClient]
    _credential: Optional[ChainedTokenCredential]
    _registration: Optional[messages.RegistrationResource]

    def __init__(self, env: Dict[str, str], *, dry_run: bool = False) -> None:
        email = env.get("ACME_EMAIL")
        subscription_id = env.get("AZURE_SUBSCRIPTION_ID")
        resource_group = env.get("AZURE_RESOURCE_GROUP")
        key_vault_url = env.get("AZURE_KEY_VAULT_URL")
        missing = [
            name
            for name, value in [
                ("ACME_EMAIL", email),
                ("AZURE_SUBSCRIPTION_ID", subscription_id),
                ("AZURE_RESOURCE_GROUP", resource_group),
                ("AZURE_KEY_VAULT_URL", key_vault_url),
            ]
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        assert email is not None
        assert subscription_id is not None
        assert resource_group is not None
        assert key_vault_url is not None

        dns_zones_raw = env.get("DNS_ZONES")
        dns_zones: Optional[List[str]] = None
        if dns_zones_raw:
            dns_zones = [zone.strip().lower().rstrip(".") for zone in dns_zones_raw.split(",") if zone.strip()]

        threshold_days = env.get("CERT_EXPIRY_THRESHOLD_DAYS")
        cert_threshold = int(threshold_days) if threshold_days else 7

        self.acme_email = email
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.key_vault_url = key_vault_url
        self.cert_expiry_threshold_days = cert_threshold
        self.dns_zones = dns_zones
        self.acme_directory_url = env.get("ACME_DIRECTORY_URL", DEFAULT_DIRECTORY_URL)
        self.dns_ttl = DEFAULT_DNS_TTL
        self.propagation_timeout = DEFAULT_PROPAGATION_TIMEOUT
        self.propagation_interval = DEFAULT_PROPAGATION_INTERVAL
        self.order_timeout = DEFAULT_ORDER_TIMEOUT
        self.dry_run = dry_run
        self._acme_client = None
        self._net = None
        self._jwk = None
        self._dns_client = None
        self._certificate_client = None
        self._secret_client = None
        self._credential = None
        self._registration = None

    def initialize_clients(self, credential_type: str = "default") -> None:
        if (
            self._credential is not None
            and self._secret_client is not None
            and self._certificate_client is not None
            and self._dns_client is not None
        ):
            return

        self._credential = get_credential(credential_type)
        self._secret_client = SecretClient(vault_url=self.key_vault_url, credential=self._credential)
        self._certificate_client = CertificateClient(vault_url=self.key_vault_url, credential=self._credential)
        self._dns_client = DnsManagementClient(credential=self._credential, subscription_id=self.subscription_id)

    def ensure_acme_account(self) -> Tuple[JWKRSA, Optional[messages.RegistrationResource]]:
        if self._secret_client is None:
            raise RuntimeError("Secret client not bound to configuration")

        secret_client = self._secret_client
        key_name, reg_name = account_secret_names(self.acme_email)
        key_value: Optional[str] = None

        try:
            key_secret = secret_client.get_secret(key_name)
            key_value = key_secret.value
            logger.info("Loaded existing ACME account key from secret %s", key_name)
        except ResourceNotFoundError:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key_bytes = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            key_value = key_bytes.decode("utf-8")
            secret_client.set_secret(key_name, key_value)
            logger.info("Generated new ACME account key and stored in secret %s", key_name)

        private_key = serialization.load_pem_private_key(key_value.encode("utf-8"), password=None)
        jwk = JWKRSA(key=private_key)
        self._jwk = jwk

        try:
            reg_secret = secret_client.get_secret(reg_name)
            registration = messages.RegistrationResource.json_loads(reg_secret.value)
            logger.info("Loaded existing ACME registration from secret %s", reg_name)
        except ResourceNotFoundError:
            registration = None
            logger.info("No ACME registration found in secret %s", reg_name)

        self._registration = registration
        return jwk, registration

    def store_registration(
        self,
        registration: messages.RegistrationResource,
    ) -> None:
        if self._secret_client is None:
            raise RuntimeError("Secret client not bound to configuration")
        secret_client = self._secret_client
        _, reg_name = account_secret_names(self.acme_email)
        secret_client.set_secret(reg_name, registration.json_dumps())
        logger.info("Stored ACME registration in secret %s", reg_name)

    def create_acme_client(
        self,
        jwk: Optional[JWKRSA] = None,
        registration: Optional[messages.RegistrationResource] = None,
    ) -> Tuple[client.ClientV2, client.ClientNetwork]:
        if jwk is None:
            jwk = self._jwk
        if jwk is None:
            raise RuntimeError("ACME account key not initialized")
        account = registration if registration is not None else self._registration
        net = client.ClientNetwork(jwk, account=account, user_agent=USER_AGENT)
        directory = client.ClientV2.get_directory(self.acme_directory_url, net)
        acme_client = client.ClientV2(directory, net)
        self._acme_client = acme_client
        self._net = net
        return acme_client, net

    def ensure_registration(
        self,
    ) -> messages.RegistrationResource:
        if self._secret_client is None:
            raise RuntimeError("Secret client not bound to configuration")
        acme_client = self._acme_client
        net = self._net
        if acme_client is None or net is None:
            raise RuntimeError("ACME client not initialized")
        registration = self._registration
        if registration:
            net.account = registration
            logger.info("Using existing ACME registration for %s", self.acme_email)
            return registration
        new_registration = acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self.acme_email,
                terms_of_service_agreed=True,
            )
        )
        net.account = new_registration
        self.store_registration(new_registration)
        logger.info("Created new ACME registration for %s", self.acme_email)
        self._registration = new_registration
        return new_registration

    def list_target_zones(self) -> List[str]:
        if self._dns_client is None:
            raise RuntimeError("DNS client not bound to configuration")
        zones: List[str] = []
        allowed = {z.lower() for z in self.dns_zones} if self.dns_zones else None
        for zone in self._dns_client.zones.list_by_resource_group(self.resource_group):
            name = zone.name.rstrip(".")
            if allowed and name.lower() not in allowed:
                continue
            zones.append(name)
        logger.info("Found %d Azure DNS zone(s) to process", len(zones))
        return zones

    def list_acme_enabled_records(
        self,
        zone_name: str,
    ) -> List[RecordSet]:
        if self._dns_client is None:
            raise RuntimeError("DNS client not bound to configuration")
        records: List[RecordSet] = []
        for record_type in ("A", "CNAME"):
            for record in self._dns_client.record_sets.list_by_type(self.resource_group, zone_name, record_type):
                metadata = (record.metadata or {})
                if metadata.get("acme", "").lower() == "true":
                    records.append(record)
        logger.info("Zone %s has %d ACME-enabled record(s)", zone_name, len(records))
        return records

    def process_zones(self) -> Tuple[List["ProvisioningResult"], int, bool]:
        zones = self.list_target_zones()
        if not zones:
            logger.info("No DNS zones found for resource group %s", self.resource_group)
            return [], 0, False

        results: List[ProvisioningResult] = []
        failures = 0

        for zone_name in zones:
            records = self.list_acme_enabled_records(zone_name)
            if not records:
                logger.info("Zone %s has no ACME-enabled A or CNAME records", zone_name)
                continue
            logger.info("Processing zone %s (%d records)", zone_name, len(records))
            for record in records:
                fqdn = record.fqdn.rstrip(".")
                try:
                    result = self.provision_certificate_for_record(zone_name, record)
                    results.append(result)
                    logger.info("%s: %s (%s)", fqdn, result.action.upper(), result.message)
                except Exception as exc:  # pylint: disable=broad-except
                    failures += 1
                    logger.exception("Failed to process %s in zone %s: %s", fqdn, zone_name, exc)

        return results, failures, True

    def provision_certificate_for_record(
        self,
        zone_name: str,
        record: RecordSet,
    ) -> "ProvisioningResult":
        if self._certificate_client is None or self._dns_client is None:
            raise RuntimeError("Service clients not bound to configuration")

        certificate_client = self._certificate_client
        dns_client = self._dns_client

        domain = record.fqdn.rstrip(".")
        certificate_name = certificate_name_for_domain(domain)
        logger.info("Processing %s (certificate %s)", domain, certificate_name)

        has_cert, expires_on = get_certificate_state(certificate_client, certificate_name)
        if has_cert and not needs_renewal(expires_on, self.cert_expiry_threshold_days):
            expires_str = expires_on.isoformat() if expires_on else "unknown"
            logger.info("Certificate %s valid until %s; skipping", certificate_name, expires_str)
            return ProvisioningResult(
                fqdn=domain,
                certificate_name=certificate_name,
                action="skipped",
                message=f"Existing certificate valid until {expires_str}",
            )

        if self.dry_run:
            if has_cert:
                expires_str = expires_on.isoformat() if expires_on else "unknown"
                message = (
                    f"Dry run: certificate expires on {expires_str}; would renew and import updated chain into Key Vault"
                )
                action = "would-renew"
                logger.info("Dry run: would renew certificate %s expiring %s", certificate_name, expires_str)
            else:
                message = "Dry run: no existing certificate; would request new certificate and import into Key Vault"
                action = "would-create"
                logger.info("Dry run: would create new certificate %s", certificate_name)
            return ProvisioningResult(
                fqdn=domain,
                certificate_name=certificate_name,
                action=action,
                message=message,
            )

        acme_client = self._acme_client
        net = self._net
        jwk = self._jwk
        if net is None or acme_client is None or jwk is None:
            raise RuntimeError("ACME client not initialized")

        registration = self._registration
        if net.account is None and registration is not None:
            net.account = registration

        private_key_pem, csr_pem = generate_domain_key_and_csr(domain)
        logger.info("Generated domain key and CSR for %s", domain)
        order = acme_client.new_order(csr_pem)
        logger.info("Created ACME order for %s with %d authorization(s)", domain, len(order.authorizations))

        published: List[Tuple[str, str]] = []

        try:
            for authorization in order.authorizations:
                identifier = authorization.body.identifier.value
                dns_challenge = next(
                    chall_body
                    for chall_body in authorization.body.challenges
                    if isinstance(chall_body.chall, challenges.DNS01)
                )
                txt_fqdn = dns_challenge.chall.validation_domain_name(identifier)
                txt_value = dns_challenge.chall.validation(jwk)
                record_name = to_zone_relative(txt_fqdn, zone_name)

                create_or_merge_txt_record(
                    dns_client,
                    self.resource_group,
                    zone_name,
                    record_name,
                    txt_value,
                    self.dns_ttl,
                )
                published.append((record_name, txt_value))

                wait_for_dns_txt(
                    txt_fqdn,
                    txt_value,
                    timeout=self.propagation_timeout,
                    interval=self.propagation_interval,
                )
                acme_client.answer_challenge(dns_challenge, dns_challenge.chall.response(jwk))
                logger.info("Answered DNS-01 challenge for identifier %s", identifier)

            deadline = _dt.datetime.now() + _dt.timedelta(seconds=self.order_timeout)
            order = acme_client.poll_authorizations(order, deadline)
            logger.info("All authorizations valid for %s; finalizing order", domain)
            finalize_success = False
            attempt = 0
            last_error: Optional[messages.Error] = None
            while attempt < 3 and not finalize_success:
                attempt += 1
                try:
                    logger.info("Finalizing order for %s (attempt %d)", domain, attempt)
                    order = acme_client.finalize_order(order, deadline)
                    finalize_success = True
                except messages.Error as err:
                    last_error = err
                    error_detail = err.detail or str(err)
                    logger.warning(
                        "Finalize attempt %d failed for %s [%s]: %s",
                        attempt,
                        domain,
                        getattr(err, "typ", "unknown"),
                        error_detail,
                    )
                    if err.typ == "urn:ietf:params:acme:error:caa" and attempt < 3:
                        sleep_duration = 5 * attempt
                        logger.info(
                            "Retrying finalize for %s after %d seconds due to CAA check failure", domain, sleep_duration
                        )
                        time.sleep(sleep_duration)
                        continue
                    break
            if not finalize_success:
                if last_error:
                    error_detail = last_error.detail or str(last_error)
                    raise RuntimeError(
                        f"ACME finalize failed for {domain}: {getattr(last_error, 'typ', 'unknown')} - {error_detail}"
                    ) from last_error
                raise RuntimeError(f"ACME finalize failed for {domain}: unknown error")
            logger.info("Finalized order for %s; importing certificate into Key Vault", domain)

            import_certificate_bundle(
                certificate_client,
                certificate_name,
                private_key_pem,
                order.fullchain_pem,
                tags={"dnsZone": zone_name, "fqdn": domain, "managed-by": USER_AGENT},
            )

            action = "renewed" if has_cert else "created"
            logger.info("Successfully %s certificate %s", action, certificate_name)
            return ProvisioningResult(
                fqdn=domain,
                certificate_name=certificate_name,
                action=action,
                message="Certificate imported into Key Vault",
            )
        finally:
            for record_name, value in published:
                try:
                    delete_txt_value_or_recordset(
                        dns_client,
                        self.resource_group,
                        zone_name,
                        record_name,
                        value,
                    )
                except Exception:
                    pass

@dataclass
class ProvisioningResult:
    fqdn: str
    certificate_name: str
    action: str
    message: str


def get_credential(credential_type: str = "default") -> ChainedTokenCredential:
    if credential_type == "env":
        return EnvironmentCredential()
    elif credential_type == "msi":
        return ManagedIdentityCredential()
    else:
        return DefaultAzureCredential()


def encode_email_for_secret(email: str) -> str:
    return email.replace("@", "-at-").replace(".", "-dot-")


def account_secret_names(email: str) -> Tuple[str, str]:
    encoded = encode_email_for_secret(email)
    return (f"acme-account-{encoded}-key", f"acme-account-{encoded}-registration")


def certificate_name_for_domain(domain: str) -> str:
    pieces: List[str] = []
    for ch in domain.lower():
        if ch.isalnum() or ch == "-":
            pieces.append(ch)
        elif ch == ".":
            pieces.append("-")
        elif ch == "*":
            pieces.append("star")
        else:
            pieces.append("-")
    name = "".join(pieces).strip("-")
    return name or "certificate"


def get_certificate_state(
    certificate_client: CertificateClient,
    certificate_name: str,
) -> Tuple[bool, Optional[_dt.datetime]]:
    try:
        certificate = certificate_client.get_certificate(certificate_name)
    except ResourceNotFoundError:
        return False, None
    expires_on = certificate.properties.expires_on
    return True, expires_on


def needs_renewal(
    expires_on: Optional[_dt.datetime],
    threshold_days: int,
) -> bool:
    if not expires_on:
        return True
    if expires_on.tzinfo is None:
        expires_on = expires_on.replace(tzinfo=_dt.timezone.utc)
    now = _dt.datetime.now(_dt.timezone.utc)
    threshold = now + _dt.timedelta(days=threshold_days)
    return expires_on <= threshold


def to_zone_relative(record_fqdn: str, zone_apex: str) -> str:
    fqdn = record_fqdn.rstrip(".")
    apex = zone_apex.rstrip(".")
    if fqdn == apex:
        return "@"
    if not fqdn.endswith("." + apex):
        raise ValueError(f"{record_fqdn} not under zone {zone_apex}")
    return fqdn[: -(len(apex) + 1)]


def create_or_merge_txt_record(
    dns_client: DnsManagementClient,
    resource_group: str,
    zone_name: str,
    record_name: str,
    value: str,
    ttl: int,
) -> None:
    logger.info("Publishing TXT record %s.%s for ACME validation", record_name, zone_name)
    try:
        current = dns_client.record_sets.get(resource_group, zone_name, record_name, "TXT")
        values = [v.value[0] for v in (current.txt_records or []) if v.value]
        if value not in values:
            values.append(value)
        params = RecordSet(ttl=current.ttl or ttl, txt_records=[TxtRecord(value=[v]) for v in values])
    except Exception:
        params = RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[value])])
    dns_client.record_sets.create_or_update(resource_group, zone_name, record_name, "TXT", params)


def delete_txt_value_or_recordset(
    dns_client: DnsManagementClient,
    resource_group: str,
    zone_name: str,
    record_name: str,
    value: str,
) -> None:
    try:
        current = dns_client.record_sets.get(resource_group, zone_name, record_name, "TXT")
    except Exception:
        logger.info("TXT record %s.%s already absent", record_name, zone_name)
        return
    values = [v.value[0] for v in (current.txt_records or []) if v.value]
    if value in values:
        values.remove(value)
    if values:
        params = RecordSet(ttl=current.ttl, txt_records=[TxtRecord(value=[v]) for v in values])
        dns_client.record_sets.create_or_update(resource_group, zone_name, record_name, "TXT", params)
        logger.info("Removed ACME validation value from TXT record %s.%s", record_name, zone_name)
    else:
        dns_client.record_sets.delete(resource_group, zone_name, record_name, "TXT")
        logger.info("Deleted TXT record %s.%s after challenge completion", record_name, zone_name)


def wait_for_dns_txt(
    fqdn: str,
    expected: str,
    timeout: int,
    interval: int,
) -> None:
    logger.info("Waiting for TXT %s to contain ACME value", fqdn)
    resolvers = []
    for nameservers in (["1.1.1.1", "1.0.0.1"], ["8.8.8.8", "8.8.4.4"]):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        resolver.nameservers = nameservers
        resolvers.append(resolver)
    deadline = time.time() + timeout
    fqdn = fqdn if fqdn.endswith(".") else fqdn + "."
    while time.time() < deadline:
        for resolver in resolvers:
            try:
                answer = resolver.resolve(fqdn, "TXT")
                values = {b"".join(rdata.strings).decode("utf-8") for rdata in answer}
                if expected in values:
                    logger.info("Found expected ACME TXT value for %s", fqdn)
                    return
            except Exception:
                pass
        time.sleep(interval)
    raise TimeoutError(f"TXT {fqdn} did not propagate with expected value in time")


def generate_domain_key_and_csr(domain: str) -> Tuple[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return key_pem, csr_pem


def import_certificate_bundle(
    certificate_client: CertificateClient,
    certificate_name: str,
    private_key_pem: str,
    fullchain_pem: str,
    tags: Optional[Dict[str, str]] = None,
) -> None:
    key_section = private_key_pem if private_key_pem.endswith("\n") else private_key_pem + "\n"
    chain_section = fullchain_pem if fullchain_pem.endswith("\n") else fullchain_pem + "\n"
    bundle = key_section + chain_section
    certificate_client.import_certificate(
        certificate_name=certificate_name,
        certificate_bytes=bundle.encode("utf-8"),
        tags=tags,
    )
