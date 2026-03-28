from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

print("Generating certificates...")

# ── CA Key and Certificate ────────────────────────────────────
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "ZeroTrustCA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1826))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256(), default_backend())
)

# Save CA files
with open("ca.key", "wb") as f:
    f.write(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("ca.crt", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("CA certificate generated")

# ── Server Key and Certificate ────────────────────────────────
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

server_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "gateway"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=730))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("gateway"),
        ]),
        critical=False
    )
    .sign(ca_key, hashes.SHA256(), default_backend())
)

# Save Server files
with open("server.key", "wb") as f:
    f.write(server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("server.crt", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))

print("Server certificate generated")

# ── Client Key and Certificate ────────────────────────────────
client_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

client_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "client"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
])

client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_name)
    .issuer_name(ca_name)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=730))
    .sign(ca_key, hashes.SHA256(), default_backend())
)

# Save Client files
with open("client.key", "wb") as f:
    f.write(client_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("client.crt", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

print("Client certificate generated")
print("")
print("All certificates generated successfully!")
print("")
print("Files created:")
print("  ca.key      - Certificate Authority private key")
print("  ca.crt      - Certificate Authority certificate")
print("  server.key  - Gateway server private key")
print("  server.crt  - Gateway server certificate")
print("  client.key  - Client private key")
print("  client.crt  - Client certificate")
