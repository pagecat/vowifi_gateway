#!/usr/bin/env python3
"""
render.py - Render /config/instance.json into Asterisk configs + the SWu launch env.

Reads the per-SIM instance descriptor (written by the manager, or hand-authored for
bring-up), fills the Jinja2 templates in /opt/vowifi/templates, and writes the final
config files. Also derives values (NAI, realm, ePDG FQDN) and computes the container
source IP used as the SWu tunnel local address.

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


def _default_gateway_ipv4():
    """The container's default-route next hop (the docker bridge gateway, e.g. 172.17.0.1), read
    from /proc/net/route. Used to source-probe the docker-bridge interface reliably even when an
    IPv4 VoWiFi tunnel has made itself the default route. Returns "" if not found."""
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.strip().split()
                # Iface Destination Gateway Flags ... ; destination 00000000 = default route,
                # skip the tunnel (ipsecN/tunN) — we want the bridge (eth0) default.
                if len(f) >= 3 and f[1] == "00000000" and int(f[3], 16) & 2:
                    if f[0].startswith(("ipsec", "tun")):
                        continue
                    gw = f[2]
                    # little-endian hex -> dotted quad
                    return ".".join(str((int(gw, 16) >> (8 * i)) & 0xFF) for i in range(4))
    except Exception:
        pass
    return ""


def container_ipv4():
    """The container's own docker-bridge IPv4 (e.g. 172.17.0.3). MUST be the bridge address, never
    the VoWiFi tunnel inner IP: it is used as the IKE source (SWU_SOURCE) and as the local SIP
    transport bind, both of which must sit on the docker bridge. A public-IP connect() probe would
    pick the tunnel's inner IP once an IPv4 PDN has made the tunnel the default route (the re-render
    after P-CSCF discovery runs post-tunnel), so probe the DOCKER GATEWAY instead — that next hop is
    always reached over the bridge, so the chosen source is the bridge IP."""
    gw = _default_gateway_ipv4()
    if gw:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((gw, 9))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        finally:
            s.close()
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


def imeisv_from_imei(imei, imeisv="", svn="00"):
    """Return a 16-digit IMEISV for the ePDG DEVICE_IDENTITY response.

    Explicit IMEISV wins (digits only, padded/truncated to 16). Otherwise derive it from the
    IMEI's first 14 digits (TAC+SNR, i.e. the IMEI without its check digit) + a 2-digit SVN
    (default '00'). Mirrors control/app/config.imeisv_from_imei so a hand-authored instance.json
    (no imeisv field) still gets a valid value. Returns '' if there is no usable IMEI/IMEISV.
    """
    isv = "".join(ch for ch in str(imeisv or "") if ch.isdigit())
    if isv:
        return (isv + "0" * 16)[:16]
    digits = "".join(ch for ch in str(imei or "") if ch.isdigit())
    if not digits:
        return ""
    base14 = digits[:14].ljust(14, "0")
    svn2 = ("".join(ch for ch in str(svn or "") if ch.isdigit()) or "00")[:2].rjust(2, "0")
    return base14 + svn2


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
        # Address family of the discovered P-CSCF. The IMS core transport must bind the same
        # family or Asterisk cannot reach the P-CSCF over the tunnel: IPv6 P-CSCF (Telus, EE)
        # -> bind [::]:5060; IPv4 P-CSCF (Vodafone UK, cp_mode=v4) -> bind 0.0.0.0:5060.
        "pcscf_is_v6": (":" in pcscf),
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
        # Bind address for the LOCAL SIP transport (external clients). Binding to the container's
        # own docker-bridge IP (not 0.0.0.0) makes Asterisk SOURCE its replies from that address:
        # DNAT rewrites an inbound LAN-client packet's destination to this IP, so the socket still
        # receives it, and the reply is sourced from it. This matters on an IPv4 IMS PDN, where the
        # SWu tunnel is the default route for ALL IPv4: a reply from a 0.0.0.0-bound UDP socket has
        # its source chosen by a fresh route lookup (-> the tunnel inner IP) and gets blackholed into
        # the ePDG, so a LAN SIP/UDP client's registration never completes. Sourcing from the
        # container IP lets the engine's source-based LAN-bypass policy route the reply out the LAN
        # link. Falls back to 0.0.0.0 if the container IP can't be determined.
        "local_bind_addr": (cfg.get("local_addr") or container_ipv4() or "0.0.0.0"),
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
    for tpl, dest in outputs.items():
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        rendered = env.get_template(tpl).render(**ctx)
        with open(dest, "w") as f:
            f.write(rendered)
        print(f"[render] {tpl} -> {dest}")

    # Export env for keeper / ami_usim / swu_ike
    env_path = os.environ.get("VOWIFI_ENV", "/run/vowifi/engine.env")
    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    with open(env_path, "w") as f:
        f.write(f"USIM_PIN={cfg.get('pin','')}\n")
        f.write(f"USIM_READER={cfg.get('reader', 'imsi:'+ctx['imsi'])}\n")
        f.write(f"USIM_ICCID={cfg.get('iccid','')}\n")
        f.write(f"VOWIFI_ID={ctx['id']}\n")
        f.write(f"MANAGER_URL={ctx['manager_url']}\n")
        # SWu (python IKEv2/IPsec) launch params — consumed by entrypoint.sh to start
        # swu_ike.py. Reader is addressed by index for swu_ike's smartcard path; source is the
        # container IP; ePDG FQDN is resolved by swu_ike.
        f.write(f"USIM_READER_INDEX={cfg.get('reader_index', 0)}\n")
        # Stable physical USB port path of the reader (e.g. "3-2"). swu_ike/pin_keeper resolve it
        # back to a live PC/SC index in-container, so the SIM is always addressed by the reader
        # that PHYSICALLY holds it — surviving pcscd re-enumerating two identical readers into a
        # different order. Empty -> fall back to USIM_READER_INDEX.
        f.write(f"USIM_READER_PORT={cfg.get('reader_port','')}\n")
        f.write(f"USIM_IMSI={ctx['imsi']}\n")
        # IMEI / IMEISV for the ePDG DEVICE_IDENTITY response. imeisv falls back to a value
        # derived from the IMEI if the instance didn't carry one (hand-authored config).
        imei_digits = "".join(ch for ch in str(cfg.get("imei", "")) if ch.isdigit())
        f.write(f"SWU_IMEI={imei_digits}\n")
        f.write(f"SWU_IMEISV={cfg.get('imeisv') or imeisv_from_imei(cfg.get('imei',''))}\n")
        f.write(f"SWU_SOURCE={ctx['local_addr']}\n")
        f.write(f"SWU_EPDG={ctx['epdg']}\n")
        f.write(f"SWU_APN={cfg.get('apn','ims')}\n")
        f.write(f"SWU_MCC={ctx['mcc']}\n")
        f.write(f"SWU_MNC={ctx['mnc']}\n")
        # ePDG identity (IDr) encoding: 'apn' (default) sends the bare APN — the form most
        # carriers' ePDGs expect and the proven-safe default; 'fqdn' builds the operator APN-FQDN
        # (<apn>.apn.epc.mnc<MNC3>.mcc<MCC3>.pub.3gppnetwork.org) that a minority of stricter
        # ePDGs require. Consumed by swu_ike.py's SWU_IDR_MODE. See config.normalize_idr_mode.
        f.write(f"SWU_IDR_MODE={cfg.get('idr_mode','apn')}\n")
        # CFG (config-request) address-family mode: 'auto' (default) walks a discovery ladder and
        # keeps the family that yields a usable PDN (see swu_ike SWU_CP_MODE / SWU_CP_MODE_ORDER);
        # 'v6' (Telus/EE), 'v4' (Vodafone UK), 'dual' pin a single family. SWU_CP_MODE_ORDER is the
        # auto ladder (carrier-DB preference first), computed by config.render_instance_json.
        f.write(f"SWU_CP_MODE={cfg.get('cp_mode','auto')}\n")
        f.write(f"SWU_CP_MODE_ORDER={cfg.get('cp_mode_order','v6,dual,v4')}\n")
        # Proactive CHILD-SA rekey period (minutes; 0 = disabled). IKEv2 does not carry SA
        # lifetime on the wire, so swu_ike uses this local-policy value to rekey the ESP SA
        # before it silently ages out (3GPP TS 24.302 7.2.2C). Set by the manager from
        # settings.rekey.minutes (default 30); hand-authored configs may omit it.
        f.write(f"SWU_CHILD_REKEY_MINUTES={cfg.get('rekey_minutes', 30)}\n")
    print(f"[render] env -> {env_path}")


if __name__ == "__main__":
    main()
