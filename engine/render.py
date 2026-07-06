#!/usr/bin/env python3
"""
render.py - Render /config/instance.json into Asterisk + strongSwan configs.

Reads the per-SIM instance descriptor (written by the manager, or hand-authored for
bring-up), fills the Jinja2 templates in /opt/vowifi/templates, and writes the final
config files. Also derives values (NAI, realm, ePDG FQDN) and computes the container
source IP for strongSwan local_addrs.

Env overrides (used by entrypoint / keeper / ami_usim after render): USIM_PIN, USIM_READER.
"""
import ipaddress
import json
import os
import socket
import subprocess
import sys

from jinja2 import Environment, FileSystemLoader

TPL_DIR = os.environ.get("VOWIFI_TPL", "/opt/vowifi/templates")
CFG_PATH = os.environ.get("VOWIFI_INSTANCE", "/config/instance.json")


def container_ipv4():
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True).split()
        for tok in out:
            try:
                ip = ipaddress.ip_address(tok)
                if ip.version == 4 and not ip.is_loopback:
                    return str(ip)
            except ValueError:
                continue
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def build_context(cfg):
    mcc = str(cfg["mcc"])
    mnc = str(cfg["mnc"]).zfill(3)
    imsi = str(cfg["imsi"])
    realm = cfg.get("realm") or f"ims.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
    epdg = cfg.get("epdg") or f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"
    nai = f"0{imsi}@nai.epc.mnc{mnc}.mcc{mcc}.3gppnetwork.org"
    # P-CSCF: explicit config wins; else a discovered address exported by entrypoint.
    pcscf = cfg.get("pcscf", "")
    if not pcscf and os.path.exists("/run/vowifi/pcscf"):
        try:
            pcscf = open("/run/vowifi/pcscf").read().strip()
        except Exception:
            pcscf = ""
    sip = cfg.get("sip", {})
    webrtc = sip.get("webrtc", {}) or {}
    ike = cfg.get("ike", {}) or {}
    default_ike = ("aes256-sha256-prfsha256-modp2048,aes128-sha256-prfsha256-modp2048,"
                   "aes256-sha1-prfsha1-modp2048,aes128-sha1-prfsha1-modp2048,"
                   "aes256-sha1-prfsha1-modp1024,aes128-sha1-prfsha1-modp1024")
    # No-PFS variants first (initial IKE_AUTH child picks one, as it always has), then
    # PFS variants (modp2048, matching the IKE DH group). The Telus ePDG accepts a
    # no-PFS CHILD_SA at IKE_AUTH but rejects a no-PFS CHILD rekey (CREATE_CHILD_SA)
    # with NO_PROPOSAL_CHOSEN -- it requires PFS on rekey. Offering both lets the SA
    # actually rekey (select a PFS proposal) instead of dying and forcing a full re-auth.
    default_esp = ("aes128-sha1,aes256-sha256,aes128-sha256,aes256-sha1,"
                   "aes128-sha1-modp2048,aes256-sha256-modp2048,"
                   "aes128-sha256-modp2048,aes256-sha1-modp2048")
    ctx = {
        "id": str(cfg.get("id", "1")),
        "imsi": imsi,
        "reader": cfg.get("reader") or f"imsi:{imsi}",
        "mcc": mcc,
        "mnc": mnc,
        "imei": cfg.get("imei", ""),
        "realm": realm,
        "epdg": epdg,
        "nai": nai,
        "msisdn": cfg.get("msisdn", ""),
        "smsc": cfg.get("smsc", ""),
        "pcscf": pcscf,          # explicit or discovered
        "local_addr": cfg.get("local_addr") or container_ipv4(),
        "ike_proposals": ike.get("proposals", default_ike),
        "esp_proposals": ike.get("esp_proposals", default_esp),
        # P-Access-Network-Info: i-wlan-node-id should be the Wi-Fi AP BSSID (MAC). The
        # carrier P-CSCF augments this; a bogus value can make some SMSCs reject MO SMS.
        "pani": (sip.get("pani") or r"IEEE-802.11\;i-wlan-node-id=ffffffffffff"),
        # Present as a real phone, not "Asterisk", to the carrier (User-Agent + Server).
        "user_agent": (sip.get("user_agent") or "iOS/26.6 iPhone"),
        # SDP identity (s=/o= lines) — Asterisk defaults s=Asterisk which fingerprints it.
        "sdp_session": (sip.get("sdp_session") or "-"),
        "sdp_owner": (sip.get("sdp_owner") or "-"),
        "ami_user": cfg.get("ami_user", "vowifi"),
        "ami_secret": cfg.get("ami_secret", "changeme"),
        "manager_url": cfg.get("manager_url", ""),
        "sip_listen": sip.get("listen_addr", "0.0.0.0"),
        "sip_tls_port": sip.get("tls_port", 5061),
        "sip_udp_port": sip.get("udp_port", 5060),
        "sip_transport": sip.get("transport", "udp"),  # udp|tcp|tls
        "external_accounts": sip.get("external", []),
        "webrtc_enable": bool(webrtc.get("enable", True)),
        "webrtc_user": webrtc.get("username", "webrtc"),
        "webrtc_password": webrtc.get("password", "webrtc-secret"),
        "webrtc_port": webrtc.get("port", 8089),
        "domain": cfg.get("domain", ""),
        # Host-reachable address to advertise to LOCAL SIP clients (Contact + SDP). The
        # container's own IP is not routable off the docker bridge, so in-dialog requests
        # (BYE) from a LAN client would be undeliverable without this. Supplied by the
        # manager (host LAN IP); empty falls back to no external address.
        "advertise_addr": sip.get("advertise_address", ""),
        # Outbound ring timeout (s) for Dial() — see extensions.conf.j2. Default 35.
        "ring_timeout": int(sip.get("ring_timeout", 35) or 35),
        # The container's own RTP bind IP (docker-bridge private, e.g. 172.17.0.2). Used as the
        # LHS of rtp.conf [ice_host_candidates] to rewrite that unreachable host candidate to
        # the host LAN IP (advertise_addr) so a LAN WebRTC browser can reach our RTP.
        "rtp_bind_addr": cfg.get("local_addr") or container_ipv4(),
        "rtp_start": cfg.get("rtp_start", 10000),
        "rtp_end": cfg.get("rtp_end", 11000),
        "debug_asterisk": cfg.get("debug", {}).get("asterisk", True),
        "debug_charon": cfg.get("debug", {}).get("charon", False),
    }
    return ctx


def main():
    with open(CFG_PATH) as f:
        cfg = json.load(f)
    ctx = build_context(cfg)

    env = Environment(loader=FileSystemLoader(TPL_DIR), trim_blocks=True, lstrip_blocks=True,
                      keep_trailing_newline=True)

    outputs = {
        "epdg.conf.j2": "/usr/local/etc/swanctl/conf.d/epdg.conf",
        "asterisk.conf.j2": "/etc/asterisk/asterisk.conf",
        "modules.conf.j2": "/etc/asterisk/modules.conf",
        "logger.conf.j2": "/etc/asterisk/logger.conf",
        "manager.conf.j2": "/etc/asterisk/manager.conf",
        "rtp.conf.j2": "/etc/asterisk/rtp.conf",
        "http.conf.j2": "/etc/asterisk/http.conf",
        "pjsip.conf.j2": "/etc/asterisk/pjsip.conf",
        "extensions.conf.j2": "/etc/asterisk/extensions.conf",
        "ami_usim.ini.j2": "/usr/local/etc/ami_usim.ini",
    }
    os.makedirs("/etc/asterisk", exist_ok=True)
    os.makedirs("/usr/local/etc/swanctl/conf.d", exist_ok=True)
    for tpl, dest in outputs.items():
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        rendered = env.get_template(tpl).render(**ctx)
        with open(dest, "w") as f:
            f.write(rendered)
        print(f"[render] {tpl} -> {dest}")

    # Export env for keeper / ami_usim / charon
    env_path = os.environ.get("VOWIFI_ENV", "/run/vowifi/engine.env")
    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    with open(env_path, "w") as f:
        f.write(f"USIM_PIN={cfg.get('pin','')}\n")
        f.write(f"USIM_READER={cfg.get('reader', 'imsi:'+ctx['imsi'])}\n")
        f.write(f"USIM_ICCID={cfg.get('iccid','')}\n")
        f.write(f"VOWIFI_ID={ctx['id']}\n")
        f.write(f"MANAGER_URL={ctx['manager_url']}\n")
    print(f"[render] env -> {env_path}")


if __name__ == "__main__":
    main()
