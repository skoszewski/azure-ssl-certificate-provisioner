#!/usr/bin/env python3
import time
import datetime

# ---------- Azure SDK ----------
from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord

# ---------- DNS propagation ----------
import dns.resolver

# ---------- ACME ----------
from acme import client, messages, challenges
from josepy.jwk import JWKRSA

# ---------- Crypto (account & domain keys, CSR) ----------
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

# =========================
# CONFIG
# =========================
# Pebble:              "https://localhost:14000/dir"  (trust Pebble CA)
# Let's Encrypt stage: "https://acme-staging-v02.api.letsencrypt.org/directory"
DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

ACCOUNT_KEY_PEM_PATH = "account.key"     # ACME account private key (PEM)
AZURE_SUBSCRIPTION_ID = "<your-subscription-id>"
AZURE_RESOURCE_GROUP = "<your-resource-group>"
AZURE_DNS_ZONE = "example.com"           # Azure DNS zone apex
FQDN = "host.example.com"                # Must be inside AZURE_DNS_ZONE

TTL_SECONDS = 30
DOMAIN_KEY_PATH = "domain_key.pem"
CSR_PATH = "domain.csr"
FULLCHAIN_PATH = "fullchain.pem"
DEADLINE_SECS = 180

# =========================
# Helpers: keys + CSR
# =========================
def generate_domain_key_and_csr(fqdn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(DOMAIN_KEY_PATH, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    with open(CSR_PATH, "wb") as f:
        f.write(csr_pem)
    return csr_pem

def load_account_jwk(pem_path: str) -> JWKRSA:
    with open(pem_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return JWKRSA(key=key)

# =========================
# DNS name handling
# =========================
def to_zone_relative(record_fqdn: str, zone_apex: str) -> str:
    """Convert FQDN to Azure DNS recordset name (relative to zone)."""
    f = record_fqdn.rstrip(".")
    z = zone_apex.rstrip(".")
    if f == z:
        return "@"
    if not f.endswith("." + z):
        raise ValueError(f"{record_fqdn} not under zone {zone_apex}")
    return f[: -(len(z) + 1)]  # strip ".zone"

# =========================
# Azure DNS helpers
# =========================
def get_dns_client() -> DnsManagementClient:
    cred = DefaultAzureCredential()
    return DnsManagementClient(credential=cred, subscription_id=AZURE_SUBSCRIPTION_ID)

def create_or_merge_txt_record(dns: DnsManagementClient, zone: str, recordset_name: str, value: str, ttl: int) -> None:
    try:
        current = dns.record_sets.get(AZURE_RESOURCE_GROUP, zone, recordset_name, "TXT")
        values = [v.value[0] for v in (current.txt_records or []) if v.value]
        if value not in values:
            values.append(value)
        params = RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[v]) for v in values])
    except Exception:
        params = RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[value])])
    dns.record_sets.create_or_update(AZURE_RESOURCE_GROUP, zone, recordset_name, "TXT", params)

def delete_txt_value_or_recordset(dns: DnsManagementClient, zone: str, recordset_name: str, value: str) -> None:
    try:
        current = dns.record_sets.get(AZURE_RESOURCE_GROUP, zone, recordset_name, "TXT")
    except Exception:
        return
    values = [v.value[0] for v in (current.txt_records or []) if v.value]
    if value in values:
        values.remove(value)
    if values:
        params = RecordSet(ttl=current.ttl, txt_records=[TxtRecord(value=[v]) for v in values])
        dns.record_sets.create_or_update(AZURE_RESOURCE_GROUP, zone, recordset_name, "TXT", params)
    else:
        dns.record_sets.delete(AZURE_RESOURCE_GROUP, zone, recordset_name, "TXT")

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
        for r in resolvers:
            try:
                ans = r.resolve(fqdn, "TXT")
                values = {b"".join(p.strings).decode("utf-8") for p in ans}
                if expected in values:
                    return
            except Exception:
                pass
        time.sleep(interval)
    raise TimeoutError(f"TXT {fqdn} did not propagate with expected value in time")

# =========================
# ACME flow (DNS-01 on Azure)
# =========================
def main():
    # 0) ACME setup
    jwk = load_account_jwk(ACCOUNT_KEY_PEM_PATH)
    # Directory can be obtained by ClientV2.get_directory(), but passing messages.Directory is fine.
    directory = client.ClientV2.get_directory(DIRECTORY_URL, client.ClientNetwork(jwk))  #  [oai_citation:6‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)
    net = client.ClientNetwork(jwk, user_agent="azure-acme-dns01/verified-1.0")
    acme_client = client.ClientV2(directory, net)  #  [oai_citation:7‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)

    # 1) Domain key + CSR for the single FQDN
    csr_pem = generate_domain_key_and_csr(FQDN)

    # 2) Create order (identifiers come from CSR)
    order = acme_client.new_order(csr_pem)  #  [oai_citation:8‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)

    # Single-domain CSR -> one authorization
    authz = order.authorizations[0]         # populated OrderResource.authorizations  [oai_citation:9‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/messages.html)
    domain = authz.body.identifier.value

    # 3) Pick DNS-01 challenge
    dns01_body = next(cb for cb in authz.body.challenges if isinstance(cb.chall, challenges.DNS01))

    # 4) Name + value via ACME helpers (library-authoritative)
    txt_fqdn  = dns01_body.chall.validation_domain_name(domain)  # "_acme-challenge.<domain>"   [oai_citation:10‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/challenges.html)
    txt_value = dns01_body.chall.validation(jwk)                 # TXT content                  [oai_citation:11‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/challenges.html)
    recordset_name = to_zone_relative(txt_fqdn, AZURE_DNS_ZONE)

    # 5) Publish TXT in Azure DNS
    dns_client = get_dns_client()
    create_or_merge_txt_record(dns_client, AZURE_DNS_ZONE, recordset_name, txt_value, TTL_SECONDS)

    try:
        # 6) Wait for public DNS to carry the validation
        wait_for_dns_txt(txt_fqdn, txt_value, timeout=420, interval=6)

        # 7) Tell ACME to validate
        acme_client.answer_challenge(dns01_body, dns01_body.chall.response(jwk))  #  [oai_citation:12‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)

        # 8) Poll authz to 'valid' (order becomes 'ready')
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=DEADLINE_SECS)
        order = acme_client.poll_authorizations(order, deadline)  #  [oai_citation:13‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)

        # 9) Finalize + obtain certificate (uses order.csr_pem internally)
        order = acme_client.finalize_order(order, deadline)       # cert -> order.fullchain_pem   [oai_citation:14‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/client.html)

        # 10) Save full chain
        with open(FULLCHAIN_PATH, "w") as f:
            f.write(order.fullchain_pem)  # OrderResource.fullchain_pem                   [oai_citation:15‡acme-python.readthedocs.io](https://acme-python.readthedocs.io/en/latest/api/messages.html)

        print(f"Issued certificate chain -> {FULLCHAIN_PATH}\nDomain key -> {DOMAIN_KEY_PATH}")

    finally:
        # 11) Cleanup TXT (remove only our value if others share the RRset)
        delete_txt_value_or_recordset(dns_client, AZURE_DNS_ZONE, recordset_name, txt_value)

if __name__ == "__main__":
    main()
