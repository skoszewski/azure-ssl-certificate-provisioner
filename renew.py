#!/usr/bin/env python3
"""
renew_cert_azure_dns.py
ACME DNS-01 renewal flow for Azure DNS zones.

- Reads existing cert to get SANs (identifiers)
- Reuses or rotates the domain key
- Creates CSR and runs ACME DNS-01 for each SAN
- Finalizes and writes new full chain
"""

import os
import sys
import time
import datetime
from pathlib import Path
from typing import List, Tuple, Set, Dict

# ---------- Azure SDK ----------
from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord

# ---------- DNS propagation ----------
import dns.resolver

# ---------- ACME ----------
from acme import client, messages, challenges
from josepy.jwk import JWKRSA

# ---------- Crypto ----------
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

# =========================
# CONFIG (adjust)
# =========================
# Pebble:              "https://localhost:14000/dir"
# Let's Encrypt stage: "https://acme-staging-v02.api.letsencrypt.org/directory"
DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

ACCOUNT_KEY_PEM_PATH = "account.key"         # ACME account private key
EXISTING_CERT_PATH = "current_fullchain.pem" # current certificate (fullchain or leaf)
EXISTING_DOMAIN_KEY_PATH = "current_domain_key.pem"

ROTATE_DOMAIN_KEY = True                     # set False to reuse current key

# Azure DNS
AZURE_SUBSCRIPTION_ID = "<your-subscription-id>"
AZURE_RESOURCE_GROUP  = "<your-resource-group>"
AZURE_DNS_ZONE        = "example.com"        # zone apex (public Azure DNS)

# Outputs
NEW_DOMAIN_KEY_PATH = "renewed_domain_key.pem"     # if rotating
NEW_CSR_PATH        = "renewed_domain.csr"
NEW_FULLCHAIN_PATH  = "renewed_fullchain.pem"

TTL_SECONDS   = 30
DEADLINE_SECS = 240   # how long to wait for authz/finalization

# =========================
# Helpers: cert/SANs, keys, CSR
# =========================
def read_dns_names_from_cert(path: str) -> List[str]:
    pem = Path(path).read_bytes()
    # Try as PEM cert; if fullchain, the first cert is fine
    cert = x509.load_pem_x509_certificate(pem)
    names: Set[str] = set()
    # Common Name (not required, but include if present)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        names.add(cn[0].value)
    # SANs
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for gn in san.get_values_for_type(x509.DNSName):
            names.add(gn)
    except x509.ExtensionNotFound:
        pass
    if not names:
        raise ValueError("No DNS names found in existing certificate")
    return sorted(names)

def load_account_jwk(pem_path: str) -> JWKRSA:
    key = serialization.load_pem_private_key(Path(pem_path).read_bytes(), password=None)
    return JWKRSA(key=key)

def load_or_generate_domain_key(rotate: bool) -> bytes:
    if rotate:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        Path(NEW_DOMAIN_KEY_PATH).write_bytes(pem)
        return pem
    # reuse current key
    return Path(EXISTING_DOMAIN_KEY_PATH).read_bytes()

def make_csr_pem(domains: List[str], domain_key_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(domain_key_pem, password=None)
    # choose a stable CN (first SAN)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subj)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
        critical=False,
    )
    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    Path(NEW_CSR_PATH).write_bytes(csr_pem)
    return csr_pem

# =========================
# DNS helpers (Azure + propagation)
# =========================
def get_dns_client() -> DnsManagementClient:
    cred = DefaultAzureCredential()
    return DnsManagementClient(credential=cred, subscription_id=AZURE_SUBSCRIPTION_ID)

def to_zone_relative(record_fqdn: str, zone_apex: str) -> str:
    f = record_fqdn.rstrip(".")
    z = zone_apex.rstrip(".")
    if f == z:
        return "@"
    if not f.endswith("." + z):
        raise ValueError(f"{record_fqdn} not under zone {zone_apex}")
    return f[: -(len(z) + 1)]

def create_or_merge_txt_record(dns: DnsManagementClient, zone: str, name: str, value: str, ttl: int) -> None:
    try:
        current = dns.record_sets.get(AZURE_RESOURCE_GROUP, zone, name, "TXT")
        values = [v.value[0] for v in (current.txt_records or []) if v.value]
        if value not in values:
            values.append(value)
        params = RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[v]) for v in values])
    except Exception:
        params = RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[value])])
    dns.record_sets.create_or_update(AZURE_RESOURCE_GROUP, zone, name, "TXT", params)

def delete_txt_value_or_recordset(dns: DnsManagementClient, zone: str, name: str, value: str) -> None:
    try:
        current = dns.record_sets.get(AZURE_RESOURCE_GROUP, zone, name, "TXT")
    except Exception:
        return
    values = [v.value[0] for v in (current.txt_records or []) if v.value]
    if value in values:
        values.remove(value)
    if values:
        params = RecordSet(ttl=current.ttl, txt_records=[TxtRecord(value=[v]) for v in values])
        dns.record_sets.create_or_update(AZURE_RESOURCE_GROUP, zone, name, "TXT", params)
    else:
        dns.record_sets.delete(AZURE_RESOURCE_GROUP, zone, name, "TXT")

def wait_for_dns_txt(fqdn: str, expected: str, timeout: int = 300, interval: int = 6) -> None:
    resolvers = []
    for ns in (["1.1.1.1", "1.0.0.1"], ["8.8.8.8", "8.8.4.4"]):
        r = dns.resolver.Resolver(configure=False)
        r.lifetime = 3.0
        r.timeout = 3.0
        r.nameservers = ns
        resolvers.append(r)
    deadline = time.time() + timeout
    fqdn = fqdn if fqdn.endswith(".") else fqdn + "."
    while time.time() < deadline:
        for res in resolvers:
            try:
                ans = res.resolve(fqdn, "TXT")
                values = {b"".join(p.strings).decode("utf-8") for p in ans}
                if expected in values:
                    return
            except Exception:
                pass
        time.sleep(interval)
    raise TimeoutError(f"TXT {fqdn} did not propagate with expected value in time")

# =========================
# ACME renewal flow
# =========================
def main():
    # 0) Collect identifiers from existing cert
    domains = read_dns_names_from_cert(EXISTING_CERT_PATH)
    print(f"Renewing names: {domains}")

    # 1) Account key / client
    jwk = load_account_jwk(ACCOUNT_KEY_PEM_PATH)
    net = client.ClientNetwork(jwk, user_agent="azure-acme-renew/1.0")
    directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
    acme_client = client.ClientV2(directory, net)

    # 2) Domain key (reuse or rotate) + CSR
    domain_key_pem = load_or_generate_domain_key(ROTATE_DOMAIN_KEY)
    csr_pem = make_csr_pem(domains, domain_key_pem)

    # 3) Create order (identifiers derived from CSR)
    order = acme_client.new_order(csr_pem)

    # 4) For each authorization, solve DNS-01
    dns_client = get_dns_client()
    published: List[Tuple[str, str]] = []  # (recordset_name, value) for cleanup

    try:
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            # choose DNS-01
            dns01_body = next(cb for cb in authz.body.challenges if isinstance(cb.chall, challenges.DNS01))
            # ACME-provided name/value
            txt_fqdn  = dns01_body.chall.validation_domain_name(domain)
            txt_value = dns01_body.chall.validation(jwk)
            recordset_name = to_zone_relative(txt_fqdn, AZURE_DNS_ZONE)

            # Publish
            create_or_merge_txt_record(dns_client, AZURE_DNS_ZONE, recordset_name, txt_value, TTL_SECONDS)
            published.append((recordset_name, txt_value))

            # Wait for visibility, then answer
            wait_for_dns_txt(txt_fqdn, txt_value, timeout=420, interval=6)
            acme_client.answer_challenge(dns01_body, dns01_body.chall.response(jwk))

        # 5) Poll all authzs until 'valid'
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=DEADLINE_SECS)
        order = acme_client.poll_authorizations(order, deadline)

        # 6) Finalize & obtain full chain (uses stored CSR from new_order)
        order = acme_client.finalize_order(order, deadline)
        Path(NEW_FULLCHAIN_PATH).write_text(order.fullchain_pem)

        # 7) Save (or rotate) domain key
        if ROTATE_DOMAIN_KEY:
            print(f"Rotated domain key -> {NEW_DOMAIN_KEY_PATH}")
        else:
            # Ensure current key persisted unchanged
            print(f"Reused domain key -> {EXISTING_DOMAIN_KEY_PATH}")

        print(f"Renewed certificate chain -> {NEW_FULLCHAIN_PATH}")

    finally:
        # 8) Cleanup all TXT values we added
        for name, value in published:
            try:
                delete_txt_value_or_recordset(dns_client, AZURE_DNS_ZONE, name, value)
            except Exception:
                pass

if __name__ == "__main__":
    main()
