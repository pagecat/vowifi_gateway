#!/usr/bin/env python3
"""
run.py - Launch the control surface over HTTPS.

Uses the configured TLS cert/key if present, otherwise auto-generates a self-signed
cert (stored under $VOWIFI_DATA/certs). Runs the FastAPI app with uvicorn.

Env:
  VOWIFI_DATA      data dir (default ./data)
  VOWIFI_HTTP_PORT override listen port (default from config.settings.http_port)
  VOWIFI_BIND      override bind address (default from config.settings.bind)
"""
import datetime
import ipaddress
import os
import socket

import uvicorn

from app import config as cfg


def _self_signed(cert_path, key_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"vowifi-gateway")])
    san = [x509.DNSName(u"localhost")]
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        san.append(x509.IPAddress(ipaddress.ip_address(host_ip)))
    except Exception:
        pass
    # Include the host LAN IP the WebUI/softphone actually connect to (the container's own
    # hostname resolves to the docker-bridge IP, not the routable host IP). Both the 8443
    # WebUI and the engine's 8089 WSS share this self-signed cert.
    adv = os.environ.get("VOWIFI_ADVERTISE_ADDR", "").strip()
    if adv:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(adv)))
        except Exception:
            pass
    san.append(x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    settings = cfg.get_settings()
    tls = settings.get("tls", {})
    port = int(os.environ.get("VOWIFI_HTTP_PORT", settings.get("http_port", 8443)))
    bind = os.environ.get("VOWIFI_BIND", settings.get("bind", "0.0.0.0"))

    if tls.get("cert_path") and os.path.exists(tls["cert_path"]) and \
            tls.get("key_path") and os.path.exists(tls["key_path"]):
        cert_path, key_path = tls["cert_path"], tls["key_path"]
    else:
        cert_path = os.path.join(cfg.DATA_DIR, "certs", "self-signed.crt")
        key_path = os.path.join(cfg.DATA_DIR, "certs", "self-signed.key")
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            print("[run] generating self-signed certificate...")
            _self_signed(cert_path, key_path)

    print(f"[run] serving https://{bind}:{port}")
    uvicorn.run("app.main:app", host=bind, port=port,
                ssl_certfile=cert_path, ssl_keyfile=key_path,
                log_level="info")


if __name__ == "__main__":
    main()
