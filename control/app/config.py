"""
config.py - Persistent manager state (global settings + per-SIM instances).

Stored as YAML at $VOWIFI_DATA/config.yaml. Threadsafe-ish via a module lock; the
manager is single-process. Instances describe SIMs; render_instance_json() converts an
instance into the engine's /config/instance.json contract.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import threading
from copy import deepcopy

import yaml

from .mcc_country import mcc_to_iso2

DATA_DIR = os.environ.get("VOWIFI_DATA", os.path.join(os.getcwd(), "data"))
CONFIG_PATH = os.path.join(DATA_DIR, "config.yaml")
_lock = threading.RLock()

DEFAULTS = {
    "settings": {
        "http_port": 8443,
        "bind": "0.0.0.0",
        "tls": {"self_signed": True, "domain": "", "cert_path": "", "key_path": ""},
        "debug": {"asterisk": True, "charon": False, "pcap": False},
        "manager_url": "",          # reachable URL engines POST events to (auto if empty)
        # Host IP/hostname advertised to LOCAL SIP/WebRTC clients (Contact + SDP).
        # Empty = auto-detect a LAN NIC (skipping common VPN/docker interfaces).
        "advertise_address": "",
        # auto_recover: after a network-class freeze (ePDG/DNS/tunnel timeout), probe
        # connectivity and auto re-provision when the network returns. Off = sticky ERROR
        # until the user presses Start / Re-provision.
        "retry": {"max": 3, "interval": 30, "auto_recover": True},
        # Proactive IKEv2 SA rekey. IKEv2 does NOT negotiate SA lifetime on the wire (RFC 7296
        # dropped it), so rekey timing is local policy (3GPP TS 24.302 clause 7.2.2C: use a
        # configured value, else an implementation value). We rekey the CHILD (ESP) SA every
        # `minutes` from its establishment. 0 disables proactive rekey (passive only — the SA
        # is only refreshed if the ePDG initiates a rekey). Default 30 min.
        "rekey": {"minutes": 30},
        # Outbound ring timeout (s): how long Asterisk lets an outgoing call ring before it
        # gives up and CANCELs. 35 covers a normal answer window; most carriers roll to
        # voicemail by ~30s. Shorter = the callee is re-alerted fewer times when unanswered.
        "ring_timeout": 35,
        # Outbound push notifications for incoming events (SMS / calls). Both channels are
        # independent and gated on their own `enabled` flag + per-event checkboxes.
        "webhook": {
            "enabled": False,
            "url": "",
            "events": {"incoming_sms": True, "incoming_call": True},
        },
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
            "events": {"incoming_sms": True, "incoming_call": True},
            # Inbound commands (the bot listening, not just notifying). Layered on purpose:
            # reading/sending SMS, restarting a line, and rewriting an eUICC are three very
            # different amounts of trust, so each is opt-in separately and all default off.
            # allowed_chats empty = only chat_id may command the bot.
            "commands": {
                "enabled": False,
                "allowed_chats": [],
                "allow_management": False,
                "allow_esim": False,
            },
        },
        # Local lpac (eSIM LPA) integration. Binary is built by `./install.sh build-lpac` into
        # $VOWIFI_DATA/lpac/ (STANDALONE layout). Empty lpac_bin → default path below.
        "esim": {
            "lpac_bin": "",
            "download_timeout": 300,
            "auto_process_notifications": True,
        },
    },
    "instances": {},
}


def default_lpac_bin() -> str:
    """Default path for the locally-built STANDALONE lpac binary."""
    return os.path.join(DATA_DIR, "lpac", "lpac")

# Port block allocation per instance index (avoids collisions across SIMs)
PORT_BASE = {"sip_udp": 5060, "sip_tls": 5061, "webrtc": 8089, "ami": 5038,
             "rtp_start": 10000, "rtp_end": 11000}
PORT_STRIDE = {"sip_udp": 10, "sip_tls": 10, "webrtc": 10, "ami": 10,
               "rtp_start": 2000, "rtp_end": 2000}


def _iface_is_lan_candidate(name: str) -> bool:
    """True when an interface is likely a host LAN NIC, not a VPN/container tunnel."""
    n = (name or "").lower()
    if not n or n == "lo":
        return False
    skip_prefixes = (
        "docker", "br-", "veth", "virbr", "cni", "flannel", "tun", "tap",
        "wg", "ipsec", "vti", "gre", "gretap", "erspan", "sit", "nlmon",
        "uk-", "nordlynx", "tailscale", "zerotier", "zt", "ppp",
    )
    return not any(n.startswith(prefix) or n == prefix.rstrip("-")
                   for prefix in skip_prefixes)


def _host_lan_ipv4() -> str:
    """Best-effort primary LAN IPv4 of the host the manager runs on. Used as the address
    Asterisk advertises to LOCAL SIP clients (Contact + SDP), so a LAN MicroSIP can route
    in-dialog requests (BYE) back to the published host port instead of the unroutable
    docker-bridge container IP.

    Prefer an address assigned to a real LAN NIC. A UDP route probe alone is not enough on
    a multi-homed host because a full-tunnel VPN can make its private tunnel address the
    source selected for 1.1.1.1; advertising that address breaks LAN RTP/RFC4733 DTMF.
    """
    # Linux fast path: inspect interface IPv4 addresses while excluding common container,
    # VPN and tunnel interface names. Prefer conventional Ethernet/Wi-Fi names.
    try:
        import fcntl
        import struct

        names = [n for n in os.listdir("/sys/class/net") if _iface_is_lan_candidate(n)]
        names.sort(key=lambda n: (not n.lower().startswith(("en", "eth", "wl")), n))
        for name in names:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    ifreq = struct.pack("256s", name[:15].encode())
                    ip = socket.inet_ntoa(
                        fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24]  # SIOCGIFADDR
                    )
                finally:
                    s.close()
                if ip and not ip.startswith("127.") and not ip.startswith("169.254.") \
                        and not ip.startswith("172.17."):
                    return ip
            except Exception:
                continue
    except Exception:
        pass

    # Fallbacks for non-Linux/minimal hosts. Keep the route-selected source, but prefer a
    # 192.168/16 address from hostname -I when the route source looks like a VPN 10/8 IP.
    route_ip = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        route_ip = s.getsockname()[0] or ""
    except Exception:
        route_ip = ""
    finally:
        s.close()

    extras: list[str] = []
    try:
        out = subprocess.check_output(
            ["hostname", "-I"], text=True, stderr=subprocess.DEVNULL
        )
        extras = [p for p in out.split()
                  if ":" not in p and not p.startswith(("127.", "169.254.", "172.17."))]
    except Exception:
        pass
    preferred = [ip for ip in extras if ip.startswith("192.168.")]
    if preferred and (not route_ip or route_ip.startswith("10.")):
        return preferred[0]
    if route_ip and not route_ip.startswith(("127.", "169.254.", "172.17.")):
        return route_ip
    return extras[0] if extras else ""


def ims_realm(mcc: str, mnc: str) -> str:
    """The carrier's IMS home-network realm, derived purely from the SIM's MCC/MNC per the
    3GPP naming scheme: ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org, with the MNC zero-padded to 3
    digits (matches the engine's render.py so control-side SMS/AMI addressing and the engine's
    registration realm agree, including for 2-digit-MNC carriers)."""
    return f"ims.mnc{str(mnc).zfill(3)}.mcc{str(mcc)}.3gppnetwork.org"


def normalize_advertise_address(value) -> str:
    """Strip and lightly validate an advertise host. Empty means automatic detection."""
    value = ("" if value is None else str(value)).strip()
    if not value:
        return ""
    if any(ch.isspace() for ch in value) or "://" in value:
        raise ValueError(
            "advertise_address must be a bare IP address or hostname "
            "(for example 192.168.6.239), not a URL"
        )
    return value


def advertise_address_managed_by_env() -> bool:
    return bool((os.environ.get("VOWIFI_ADVERTISE_ADDR") or "").strip())


def advertise_address(settings: dict) -> str:
    """Resolve the address advertised to local SIP clients.

    Precedence is installer/environment pin > stored Settings value > TLS domain >
    LAN auto-detection. The environment override must win even when TLS has a domain,
    because multi-homed installations use it to pin the host-side RTP/Contact address.
    """
    env = normalize_advertise_address(os.environ.get("VOWIFI_ADVERTISE_ADDR", ""))
    if env:
        return env
    stored = normalize_advertise_address(settings.get("advertise_address", ""))
    if stored:
        return stored
    tls_domain = ((settings.get("tls", {}) or {}).get("domain") or "").strip()
    if tls_domain:
        return tls_domain
    return _host_lan_ipv4() or ""


def _ensure():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(DEFAULTS, f)


_cached: dict | None = None
_cached_key: tuple | None = None


def load() -> dict:
    """Read + merge the config. Cached on the file's mtime/size because get_instance,
    list_instances and get_settings all funnel through here and are called dozens of times
    per request cycle — re-reading and re-parsing the YAML each time is disk work done under
    a lock the event loop also waits on. Callers mutate what they get, so hand out a copy."""
    global _cached, _cached_key
    with _lock:
        _ensure()
        try:
            st = os.stat(CONFIG_PATH)
            cache_key = (st.st_mtime_ns, st.st_size)
        except OSError:
            cache_key = None
        if cache_key is not None and cache_key == _cached_key and _cached is not None:
            return deepcopy(_cached)
        with open(CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
        # merge defaults (shallow for settings)
        out = deepcopy(DEFAULTS)
        out["settings"].update(data.get("settings", {}))
        if "tls" in data.get("settings", {}):
            out["settings"]["tls"] = {**DEFAULTS["settings"]["tls"], **data["settings"]["tls"]}
        out["settings"]["retry"] = {**DEFAULTS["settings"]["retry"],
                                    **(data.get("settings", {}).get("retry", {}))}
        out["settings"]["rekey"] = {**DEFAULTS["settings"]["rekey"],
                                    **(data.get("settings", {}).get("rekey", {}))}
        # webhook / telegram: merge one level deep (like tls/retry) so a saved config that
        # predates these keys — or omits the nested `events` map — still gets full defaults.
        for key in ("webhook", "telegram"):
            saved = data.get("settings", {}).get(key, {}) or {}
            merged = {**DEFAULTS["settings"][key], **saved}
            merged["events"] = {**DEFAULTS["settings"][key]["events"],
                                **(saved.get("events", {}) or {})}
            if "commands" in DEFAULTS["settings"][key]:
                merged["commands"] = {**DEFAULTS["settings"][key]["commands"],
                                      **(saved.get("commands", {}) or {})}
            out["settings"][key] = merged
        esim_saved = data.get("settings", {}).get("esim", {}) or {}
        out["settings"]["esim"] = {**DEFAULTS["settings"]["esim"], **esim_saved}
        out["instances"] = data.get("instances", {})
        _cached, _cached_key = out, cache_key
        return deepcopy(out)


def esim_settings() -> dict:
    """Resolved eSIM/lpac settings (fills empty lpac_bin with the default path)."""
    s = dict(get_settings().get("esim") or {})
    if not (s.get("lpac_bin") or "").strip():
        s["lpac_bin"] = default_lpac_bin()
    return s


def save(data: dict):
    global _cached, _cached_key
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w") as f:
            yaml.safe_dump(data, f, sort_keys=False)
        os.replace(tmp, CONFIG_PATH)
        # Don't rely on the new mtime differing from the cached one; drop it outright.
        _cached, _cached_key = None, None


def get_settings() -> dict:
    return load()["settings"]


def public_settings() -> dict:
    """Settings payload for the WebUI, including resolved advertise-address diagnostics."""
    settings = get_settings()
    try:
        stored = normalize_advertise_address(settings.get("advertise_address", ""))
    except ValueError:
        # Do not let a malformed legacy value make the Settings endpoint unusable.
        stored = ""
    settings["advertise_address"] = stored
    settings["advertise_address_effective"] = advertise_address(settings)
    settings["advertise_address_managed_by_env"] = advertise_address_managed_by_env()
    settings["advertise_address_detected"] = _host_lan_ipv4() or ""
    # The bot token is a bearer credential for an account that can now be commanded, and this
    # payload goes to every browser that opens Settings. Report only whether one is set; an
    # empty token in a patch is understood as "leave it alone" (see update_settings).
    tg = dict(settings.get("telegram") or {})
    tg["bot_token_set"] = bool((tg.get("bot_token") or "").strip())
    tg["bot_token"] = ""
    settings["telegram"] = tg
    return settings


def update_settings(patch: dict) -> dict:
    data = load()
    patch = dict(patch or {})
    for key in ("advertise_address_effective", "advertise_address_managed_by_env",
                "advertise_address_detected"):
        patch.pop(key, None)
    if "advertise_address" in patch:
        patch["advertise_address"] = normalize_advertise_address(
            patch.get("advertise_address")
        )
    # public_settings blanks the bot token, so the WebUI never has the real one to send back.
    # An empty token therefore means "unchanged" — the same rule the SIM PIN and the SIP
    # account passwords already follow — otherwise every Settings save would erase it.
    if isinstance(patch.get("telegram"), dict):
        tg_patch = dict(patch["telegram"])
        tg_patch.pop("bot_token_set", None)
        if not str(tg_patch.get("bot_token") or "").strip():
            tg_patch["bot_token"] = (data["settings"].get("telegram") or {}).get("bot_token", "")
        patch["telegram"] = tg_patch
    try:
        previous = normalize_advertise_address(
            data["settings"].get("advertise_address", "")
        )
    except ValueError:
        previous = ""
    data["settings"].update(patch)
    save(data)
    try:
        current = normalize_advertise_address(
            data["settings"].get("advertise_address", "")
        )
    except ValueError:
        current = ""
    # Refresh the host-mounted instance.json files. Running Asterisk instances still need
    # an explicit Stop -> Start; this makes the new address ready for that next start.
    if "advertise_address" in patch or current != previous:
        for inst in list((data.get("instances") or {}).values()):
            try:
                write_instance_json(inst, data["settings"])
            except Exception:
                pass
    return public_settings()


def list_instances() -> list:
    return list(load()["instances"].values())


def get_instance(iid: str) -> dict | None:
    return load()["instances"].get(str(iid))


def _alloc_ports(index: int) -> dict:
    """The nominal port block for an instance index (no conflict checking)."""
    return {k: PORT_BASE[k] + index * PORT_STRIDE[k] for k in PORT_BASE}


# How many RTP host ports the engine actually publishes (engine.start binds rtp_start..+60).
RTP_SPAN = 60
# Valid user-selectable SIP port range (avoid well-known/privileged ports).
MIN_USER_PORT, MAX_USER_PORT = 1024, 65535


def _block_ports(block: dict) -> set[int]:
    """Every host port a port-block occupies: the 4 fixed services + the RTP span."""
    used = {block["sip_udp"], block["sip_tls"], block["webrtc"], block["ami"]}
    used |= set(range(block["rtp_start"], block["rtp_start"] + RTP_SPAN))
    return used


def _reserved_ports(data: dict, exclude_iid: str | None = None) -> set[int]:
    """All host ports already reserved by OTHER instances (from their stored port blocks)."""
    used: set[int] = set()
    for iid, inst in data["instances"].items():
        if exclude_iid is not None and str(iid) == str(exclude_iid):
            continue
        p = inst.get("ports")
        if p:
            used |= _block_ports(p)
    return used


def _host_port_free(port: int) -> bool:
    """True if the host isn't already LISTENing on this TCP or UDP port. Best-effort:
    we try to bind; EADDRINUSE => taken. Uses SO_REUSEADDR off so an active listener
    is detected. Any unexpected error is treated as 'free' (don't block provisioning)."""
    for fam, typ in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM)):
        s = socket.socket(fam, typ)
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            return False
        except Exception:
            pass
        finally:
            s.close()
    return True


def _block_free(block: dict, reserved: set[int]) -> bool:
    """A candidate block is usable if none of its ports collide with reserved ports and
    none of its 4 service ports are already listening on the host."""
    bp = _block_ports(block)
    if bp & reserved:
        return False
    # Only probe the 4 service ports on the host (probing 60 RTP ports every try is slow;
    # RTP conflicts are caught by the reserved-set check against other instances).
    for port in (block["sip_udp"], block["sip_tls"], block["webrtc"], block["ami"]):
        if not _host_port_free(port):
            return False
    return True


def alloc_ports_auto(data: dict, exclude_iid: str | None = None) -> dict:
    """Automatic port allocation: scan index blocks from 0 upward and take the first whose
    whole port block collides with neither another instance nor a live host listener. This
    is the default behaviour. Starting at 0 (not next_index) means re-provisioning a line
    back to Auto reclaims the lowest free block instead of drifting ever upward."""
    reserved = _reserved_ports(data, exclude_iid)
    for index in range(0, 500):                    # generous bound; ~500 lines is absurd
        block = _alloc_ports(index)
        if max(_block_ports(block)) > MAX_USER_PORT:
            break
        if _block_free(block, reserved):
            return block
    raise ValueError("no free port block available for a new line")


def ports_from_sip_base(data: dict, sip_udp: int, exclude_iid: str | None = None) -> dict:
    """Manual port selection: the user picks the SIP UDP port; the rest of the block is
    derived from it at the same offsets as the nominal layout, so one number configures
    the whole line. Validates range and checks the whole derived block for conflicts.
    Raises ValueError with a user-facing message on any problem."""
    if not isinstance(sip_udp, int):
        raise ValueError("port must be a number")
    if not (MIN_USER_PORT <= sip_udp <= MAX_USER_PORT):
        raise ValueError(f"port must be between {MIN_USER_PORT} and {MAX_USER_PORT}")
    # Derive the block from the SIP UDP base using the nominal per-service offsets.
    base0 = _alloc_ports(0)
    off = {k: base0[k] - base0["sip_udp"] for k in PORT_BASE}   # sip_udp offset = 0
    block = {k: sip_udp + off[k] for k in PORT_BASE}
    if max(_block_ports(block)) > MAX_USER_PORT:
        raise ValueError(f"port {sip_udp} is too high — its RTP range would exceed {MAX_USER_PORT}")
    reserved = _reserved_ports(data, exclude_iid)
    clash = _block_ports(block) & reserved
    if clash:
        if sip_udp in clash or block["sip_tls"] in clash:
            raise ValueError(f"port {sip_udp} is already used by another line. "
                             f"Choose a different port or use Automatic.")
        # A derived service/RTP port (WebRTC/control/RTP) overlaps a neighbouring line's
        # block. Tell the user what to avoid without exposing internal port math.
        raise ValueError(f"port {sip_udp} overlaps another line's port range "
                         f"(conflict at {min(clash)}). Try a port at least 10 away, or "
                         f"use Automatic.")
    for port, name in ((block["sip_udp"], "SIP/UDP"), (block["sip_tls"], "SIP/TLS"),
                       (block["webrtc"], "WebRTC"), (block["ami"], "control")):
        if not _host_port_free(port):
            raise ValueError(f"port {port} ({name}) is already in use on the host. "
                             f"Choose a different port or use Automatic.")
    return block


def next_index(data: dict) -> int:
    used = {inst.get("index", 0) for inst in data["instances"].values()}
    i = 0
    while i in used:
        i += 1
    return i


_SIP_RESERVED_USERNAMES = frozenset({
    "global", "system", "volte_ims",
    "endpoint-local", "auth-local", "aor-local",
    "transport-local", "transport-wss",
})


def validate_sip_username(username: str) -> None:
    """Reject a name Asterisk reserves for itself. Raises ValueError."""
    name = str(username or "").strip()
    if not name:
        raise ValueError("a SIP username cannot be empty")
    if name in _SIP_RESERVED_USERNAMES:
        raise ValueError(
            f"SIP username '{name}' is reserved (used by the built-in softphone "
            "or Asterisk internals). Choose a different name."
        )


def _sip_username_line_in(data: dict, username: str, exclude_iid: str | None = None) -> str | None:
    name = str(username or "").strip()
    if not name:
        return None
    for iid, inst in (data.get("instances") or {}).items():
        if exclude_iid is not None and str(iid) == str(exclude_iid):
            continue
        for account in ((inst.get("sip") or {}).get("external") or []):
            if isinstance(account, dict) and str(account.get("username") or "").strip() == name:
                return str(iid)
    return None


def sip_username_line(username: str, exclude_iid: str | None = None) -> str | None:
    """The line already using this external SIP username, if any.

    Names have to be unique across lines and not merely within one, because the
    userbot sidecar registers every line's account from a single PJSUA2
    endpoint: two accounts sharing a `sip:user@host` identity make an inbound
    call ambiguous, and PJSIP hands it to whichever it matches first.
    """
    return _sip_username_line_in(load(), username, exclude_iid)


def validate_sip_external_usernames(sip: dict | None) -> None:
    """Reject external SIP names that would collide in the rendered pjsip config."""
    sip = sip or {}
    external = sip.get("external") or []
    webrtc_user = str(
        ((sip.get("webrtc") or {}).get("username") or "webrtc")
    ).strip()
    reserved = set(_SIP_RESERVED_USERNAMES)
    if webrtc_user:
        reserved.add(webrtc_user)

    seen: dict[str, int] = {}
    for index, account in enumerate(external):
        if not isinstance(account, dict):
            continue
        username = str(account.get("username") or "").strip()
        if not username:
            continue
        if username in reserved:
            raise ValueError(
                f"SIP username '{username}' is reserved (used by the built-in "
                "softphone or Asterisk internals). Choose a different name."
            )
        previous = seen.get(username)
        if previous is not None:
            raise ValueError(
                f"SIP username '{username}' is used more than once on this line "
                f"(accounts #{previous + 1} and #{index + 1}). Each account needs "
                "a unique username."
            )
        seen[username] = index


def merge_external_sip_accounts(new_list, old_list) -> list:
    """Preserve an external SIP secret when a save omits or blanks its password."""
    old_by_username = {}
    for account in old_list or []:
        if not isinstance(account, dict):
            continue
        username = str(account.get("username") or "").strip()
        if username:
            old_by_username[username] = account

    merged = []
    for account in new_list or []:
        if not isinstance(account, dict):
            continue
        username = str(account.get("username") or "").strip()
        if not username:
            continue
        if "password" in account and str(account.get("password") or "").strip():
            password = str(account.get("password"))
        else:
            password = str((old_by_username.get(username) or {}).get("password") or "")
        if not password:
            raise ValueError(
                f"SIP account '{username}' needs a password "
                "(third-party SIP clients will get Unauthorized without one)."
            )
        merged.append({**account, "username": username, "password": password})
    return merged


def upsert_instance(inst: dict) -> dict:
    data = load()
    iid = str(inst["id"])
    # Runtime-only fields sometimes ride along on the instance object (the API returns
    # instances with a computed `status` and `has_pin`); never persist them to config.
    inst = {k: v for k, v in inst.items() if k not in ("status", "has_pin")}
    existing = data["instances"].get(iid, {})
    # An ICCID names exactly one line: it is how a physical card is matched to its config, and
    # every lookup takes the FIRST match. Two lines sharing one would silently capture each
    # other's card, port relearning and identity verdict, so refuse it at the door.
    new_iccid = str(inst.get("iccid") or "").strip()
    if new_iccid:
        for other_id, other in data["instances"].items():
            if str(other_id) != iid and str(other.get("iccid") or "").strip() == new_iccid:
                raise ValueError(f"ICCID {new_iccid} already belongs to line {other_id}")
    if "index" not in existing:
        inst["index"] = next_index(data)
    else:
        inst["index"] = existing["index"]
    # Port block: keep an existing/explicit block; otherwise auto-allocate a conflict-free
    # one (checks other instances AND live host listeners, stepping forward on collision).
    if "ports" not in inst:
        inst["ports"] = existing.get("ports") or alloc_ports_auto(data, exclude_iid=iid)
    # Treat an empty/missing ami_secret the same: a WebUI save that carries a blank
    # secret must never overwrite the real one (control would then log in to the
    # engine's Asterisk with the wrong credential forever).
    if not inst.get("ami_secret"):
        inst.pop("ami_secret", None)
        inst["ami_secret"] = existing.get("ami_secret") or secrets.token_urlsafe(16)
    # The SIM PIN is a locally-saved credential tied to this IMSI/ICCID; it is used on
    # every engine start. A config edit that doesn't carry a (new, non-empty) PIN must NOT
    # wipe the stored one — otherwise saving unrelated fields (IMEI, SMSC, SIP accounts…)
    # would silently drop the PIN and break the next start. Only an explicit non-empty PIN
    # updates it; clearing is done deliberately elsewhere (wrong-PIN / PIN-removed handling).
    if not inst.get("pin"):
        inst.pop("pin", None)
        if existing.get("pin"):
            inst["pin"] = existing["pin"]
    # Merge SIP settings one level deeper than the instance itself. In particular, a
    # password field intentionally omitted by the WebUI must keep the saved credential.
    if "sip" in inst:
        old_sip = existing.get("sip") or {}
        new_sip = inst.get("sip") or {}
        merged_sip = {**old_sip, **new_sip}
        if "webrtc" in old_sip or "webrtc" in new_sip:
            merged_sip["webrtc"] = {
                **(old_sip.get("webrtc") or {}),
                **(new_sip.get("webrtc") or {}),
            }
        if "external" in new_sip:
            merged_sip["external"] = merge_external_sip_accounts(
                new_sip.get("external"), old_sip.get("external")
            )
        inst["sip"] = merged_sip
    merged = {**existing, **inst}
    # Ensure a STABLE WebRTC softphone credential (used by both the Asterisk config and
    # the softphone provisioning endpoint — they must match).
    sip = merged.setdefault("sip", {})
    wr = sip.setdefault("webrtc", {})
    wr.setdefault("username", "webrtc")
    if not wr.get("password"):
        prev = (existing.get("sip", {}) or {}).get("webrtc", {}) or {}
        wr["password"] = prev.get("password") or secrets.token_urlsafe(12)
    validate_sip_external_usernames(sip)
    # Cross-line uniqueness, but only for names this save introduces: a clash
    # that predates it is not something the user can fix from this form.
    had = {str(a.get("username") or "").strip()
           for a in ((existing.get("sip") or {}).get("external") or [])
           if isinstance(a, dict)}
    for account in (sip.get("external") or []):
        if not isinstance(account, dict):
            continue
        name = str(account.get("username") or "").strip()
        if not name or name in had:
            continue
        clash = _sip_username_line_in(data, name, exclude_iid=iid)
        if clash:
            raise ValueError(
                f"SIP username '{name}' already belongs to line {clash}. Names must be "
                "unique across lines, or the userbot cannot register them all at once."
            )
    data["instances"][iid] = merged
    save(data)
    return merged


def clear_pin(iid: str) -> bool:
    """Delete the saved SIM PIN for an instance. Returns True if a PIN was removed. The
    line will then require the PIN to be re-entered before it can start again (used by the
    'Delete saved PIN' action and by wrong-PIN / PIN-removed handling)."""
    data = load()
    inst = data["instances"].get(str(iid))
    if not inst:
        return False
    had = bool(inst.get("pin"))
    inst["pin"] = ""
    save(data)
    return had


def delete_instance(iid: str):
    data = load()
    data["instances"].pop(str(iid), None)
    save(data)


def normalize_imei(imei: str) -> str:
    """Strip any formatting (dashes/spaces) from an IMEI and return just the digits."""
    return "".join(ch for ch in (imei or "") if ch.isdigit())


def imeisv_from_imei(imei: str, imeisv: str = "", svn: str = "00") -> str:
    """Return a 16-digit IMEISV.

    IMEISV = 14-digit IMEI base (TAC+SNR, i.e. the IMEI WITHOUT its Luhn check digit) + a
    2-digit SVN (Software Version Number). If the caller supplied an explicit IMEISV we honour
    it (digits only, padded/truncated to 16); otherwise we derive it from the IMEI's first 14
    digits and append the given SVN (default '00'). Used to answer the ePDG's DEVICE_IDENTITY
    request. Returns '' if there is no usable IMEI/IMEISV.
    """
    isv = "".join(ch for ch in (imeisv or "") if ch.isdigit())
    if isv:
        return (isv + "0" * 16)[:16]
    digits = normalize_imei(imei)
    if not digits:
        return ""
    base14 = digits[:14].ljust(14, "0")   # drop the 15th (check) digit; TAC+SNR = 14 digits
    svn2 = ("".join(ch for ch in (svn or "") if ch.isdigit()) or "00")[:2].rjust(2, "0")
    return base14 + svn2


def _clamp_rekey(v) -> int:
    """0 disables proactive rekey; otherwise clamp to 1..1440 minutes."""
    try:
        m = int(v)
    except (TypeError, ValueError):
        return 30
    if m <= 0:
        return 0
    return max(1, min(1440, m))


def normalize_apn(apn: str) -> str:
    """The APN (access point name) to attach to for VoWiFi. Blank falls back to the standard
    IMS APN 'ims'. Lowercased and trimmed; a carrier that needs a different APN (e.g. a data
    APN or a regional IMS APN) can set it explicitly."""
    a = (apn or "").strip().lower()
    return a or "ims"


def normalize_idr_mode(mode: str) -> str:
    """How the ePDG identity (IDr) is encoded in IKE_AUTH (3GPP TS 24.302 clause 7.2.2.1):
      'apn' (default) — the bare APN string (e.g. 'ims'). Most carriers' ePDGs expect this, and
                        it is the empirically-proven, widely-accepted form.
      'fqdn'          — the operator APN-FQDN a real UE builds:
                        <apn>.apn.epc.mnc<MNC3>.mcc<MCC3>.pub.3gppnetwork.org
                        A minority of stricter ePDGs require this form; note it is rejected by some
                        networks (they fail EAP with AUTHENTICATION_FAILED on it).
    Defaults to 'apn' as the safe, widely-accepted form; falls back to 'apn' for any unrecognised
    value. Set 'fqdn' per-line only for a carrier that needs it."""
    m = (mode or "").strip().lower()
    return m if m in ("apn", "fqdn") else "apn"


def normalize_cp_mode(mode: str) -> str:
    """Address family of the SWu CFG (config) request, which MUST match the carrier's IMS PDN or
    the ePDG rejects the PDN connection at the final IKE_AUTH (after EAP succeeds):
      'auto' (default) — try a discovery ladder (carrier-DB preference first) and keep the family
                         that yields a usable PDN; the engine reports the winner back and the line
                         is repinned to it. Seamless: no per-carrier knowledge needed from the user.
      'v6'             — request INTERNAL_IP6_ADDRESS + P_CSCF_IP6_ADDRESS. Telus/EE (IPv6 IMS).
      'v4'             — request the IPv4 attrs. Vodafone UK (IPv4 IMS; v6-only -> Notify 16375).
      'dual'           — request both (note dual suppresses Telus's P-CSCF).
    Defaults to 'auto'; falls back to 'auto' for any unrecognised value."""
    m = (mode or "").strip().lower()
    return m if m in ("auto", "v6", "v4", "dual") else "auto"


# TS 24.229 clause 7.2A.4.3 access-type values used for WLAN/VoWiFi, plus 3GPP-WLAN which
# appears in osmocom/sysmocom reference configs (historical / carrier-specific).
PANI_ACCESS_TYPES = frozenset({
    "IEEE-802.11", "IEEE-802.11a", "IEEE-802.11b", "IEEE-802.11g", "IEEE-802.11n",
    "IEEE-802.11ac", "IEEE-802.11ax", "IEEE-802.11be", "IEEE-802.11j", "IEEE-802.11p",
    "IEEE-802.11y", "IEEE-802.11ad", "IEEE-802.11af", "IEEE-802.11ah", "IEEE-802.11aj",
    "IEEE-802.11ay", "IEEE-802.11bd", "3GPP-WLAN",
})


def normalize_pani_country(c) -> str:
    """ISO 3166-1 alpha-2 country code for PANI country=. Strip + upper-case; invalid -> ''."""
    s = "".join(ch for ch in str(c or "").strip().upper() if ch.isalpha())
    return s if len(s) == 2 else ""


def normalize_pani_node_id(m) -> str:
    """WLAN BSSID / AP MAC for i-wlan-node-id: strip : - . spaces, lower-case hex, 12 digits."""
    s = "".join(ch for ch in str(m or "") if ch.isalnum()).lower()
    if len(s) == 12 and all(ch in "0123456789abcdef" for ch in s):
        return s
    return ""


def normalize_pani_access_type(t) -> str:
    """PANI access-type; unknown values fall back to IEEE-802.11."""
    s = (t or "").strip()
    return s if s in PANI_ACCESS_TYPES else "IEEE-802.11"


def _sip_bool(sip: dict, key: str, default: bool) -> bool:
    """Read a sip.* bool that may be absent (legacy configs) or explicitly False."""
    if key not in sip:
        return default
    v = sip.get(key)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return default


def build_pani(inst: dict, sip: dict | None = None) -> str:
    """Compose the unescaped P-Access-Network-Info value for the engine.

    Resolution (industry VoWiFi convention; see RFC 7315 extension-access-info + TS 24.229
    i-wlan-node-id coding rules):
      1. sip.pani non-empty → raw override (caller owns the exact header value).
      2. Else access-type (default IEEE-802.11).
      3. If pani_country_enable (default True): country=XX from explicit pani_country, else
         MCC→ISO via mcc_to_iso2(inst.mcc).
      4. If pani_node_id_enable (default False): append i-wlan-node-id=<12 hex>.
      5. Optional pani_local_time_zone (config-only; 24.229 says UE should not insert it).

    Returns a clean value (no Asterisk \\; escaping) — engine/render.py escapes for pjsip.conf.
    Default shape matches a working UE trace: ``IEEE-802.11;country=GB``.
    """
    sip = sip if sip is not None else (inst.get("sip") or {})
    raw = (sip.get("pani") or "").strip()
    if raw:
        return raw

    parts = [normalize_pani_access_type(sip.get("pani_access_type"))]

    if _sip_bool(sip, "pani_country_enable", True):
        country = normalize_pani_country(sip.get("pani_country"))
        if not country:
            country = mcc_to_iso2(inst.get("mcc"))
        if country:
            parts.append(f"country={country}")

    if _sip_bool(sip, "pani_node_id_enable", False):
        node = normalize_pani_node_id(sip.get("pani_node_id"))
        if node:
            parts.append(f"i-wlan-node-id={node}")

    tz = (sip.get("pani_local_time_zone") or "").strip()
    if tz:
        # Quote if the value contains spaces / special chars and isn't already quoted.
        if " " in tz or ";" in tz:
            if not (tz.startswith('"') and tz.endswith('"')):
                tz = '"' + tz.replace('"', '') + '"'
        parts.append(f"local-time-zone={tz}")

    return ";".join(parts)


# Carrier CP-mode preference database, keyed by "mcc-mnc" (MNC as stored on the line — may be 2- or
# 3-digit; render_instance_json tries both). Value = the family a real UE uses on that network, used
# as the FIRST rung of the auto discovery ladder (a starting hint, NOT a hard override — the ladder
# still falls back if it fails post-EAP). Extend as new carriers are characterised.
CARRIER_CP_PREF = {
    "302-220": "v6",     # Telus (Canada) — IPv6 IMS PDN; v4/dual returns no P-CSCF
    "234-15":  "dual",   # Vodafone UK — IPv4 IMS PDN; v6-only rejected with private Notify 16375
    "234-30":  "v6",     # EE (UK) — IPv6 IMS PDN
    "234-33":  "v6",     # EE/CTExcel MVNO (UK) — IPv6 IMS PDN
}

# Default auto discovery ladder for carriers not in CARRIER_CP_PREF. v6 first (most VoLTE/VoWiFi IMS
# cores are IPv6 and connect on attempt 1); dual catches v4/dual-only carriers (e.g. Vodafone); v4
# last. The DB-preferred family (if any) is moved to the front and deduped by render_instance_json.
CP_MODE_LADDER_DEFAULT = ["v6", "dual", "v4"]


def cp_mode_order_for(mcc: str, mnc: str) -> str:
    """Compute the comma-separated auto discovery ladder for a line: carrier-DB preference (matched
    on mcc-mnc, trying both the stored MNC and its 3-digit zfill) first, then the default ladder,
    deduped. Consumed by the engine as SWU_CP_MODE_ORDER."""
    order = []
    pref = None
    for key in ("%s-%s" % (mcc, mnc), "%s-%s" % (str(mcc).zfill(3), str(mnc).zfill(3)),
                "%s-%s" % (mcc, str(mnc).lstrip("0") or mnc)):
        if key in CARRIER_CP_PREF:
            pref = CARRIER_CP_PREF[key]
            break
    if pref:
        order.append(pref)
    for m in CP_MODE_LADDER_DEFAULT:
        if m not in order:
            order.append(m)
    return ",".join(order)


def render_instance_json(inst: dict, settings: dict) -> dict:
    """Convert a stored instance into the engine /config/instance.json contract."""
    ports = inst.get("ports", _alloc_ports(inst.get("index", 0)))
    sip = inst.get("sip", {}) or {}
    webrtc = sip.get("webrtc", {}) or {}
    return {
        "id": str(inst["id"]),
        "imsi": inst["imsi"],
        "mcc": inst["mcc"],
        "mnc": inst["mnc"],
        "imei": inst.get("imei", ""),
        # IMEISV (16 digits) for the ePDG DEVICE_IDENTITY response. Explicit stored value wins;
        # otherwise auto-derive from the IMEI (14-digit base + '00' SVN). Empty stays empty
        # (swu_ike then derives its own or falls back).
        "imeisv": inst.get("imeisv", "") or imeisv_from_imei(inst.get("imei", ""), inst.get("imeisv", "")),
        "pin": inst.get("pin", ""),
        "reader": inst.get("reader") or f"imsi:{inst['imsi']}",
        # PC/SC reader index the engine addresses the SIM by (passed to swu_ike as -m / pin_keeper
        # / ami_usim). MUST be emitted: without it the engine's render.py defaults to 0, so a line
        # on any reader other than 0 authenticates against the wrong physical SIM (USIM AUTHENTICATE
        # returns 0x9862 "incorrect MAC"). Kept in sync with the live ICCID-matched reader at start.
        "reader_index": inst.get("reader_index", 0),
        # Stable physical USB port path of the reader (e.g. "3-2"). The engine resolves this back
        # to a live PC/SC index in-container so its self-heal restarts address the right physical
        # reader even when pcscd re-enumerates two identical readers in a different order. Empty
        # -> engine falls back to reader_index. See control/app/usbreader.py.
        "reader_port": inst.get("reader_port", ""),
        "iccid": inst.get("iccid", ""),
        "msisdn": inst.get("msisdn", ""),
        "smsc": inst.get("smsc", ""),
        "pcscf": inst.get("pcscf", ""),
        "ami_user": inst.get("ami_user", "vowifi"),
        "ami_secret": inst["ami_secret"],
        # Where engine notify.py POSTs events. Explicit setting wins; else VOWIFI_MANAGER_URL
        # env (the installer sets this to the PUBLISHED host port when the control plane runs
        # in a bridge-networked container with a non-8443 port map); else the default assumes
        # a 1:1 host.docker.internal:<http_port> mapping.
        "manager_url": settings.get("manager_url")
                       or os.environ.get("VOWIFI_MANAGER_URL")
                       or f"https://host.docker.internal:{settings.get('http_port', 8443)}",
        "domain": settings.get("tls", {}).get("domain", ""),
        "rtp_start": ports["rtp_start"],
        # The engine publishes only rtp_start..rtp_start+RTP_SPAN-1 host ports (engine.start),
        # so the Asterisk RTP pool (rtp.conf rtpend) MUST match that published window — a port
        # picked above it would be unreachable from a LAN WebRTC client → no/one-way audio. Cap
        # rtp_end to the published span rather than the (larger) block-allocation rtp_end.
        "rtp_end": min(ports["rtp_end"], ports["rtp_start"] + RTP_SPAN - 1),
        "sip": {
            "listen_addr": sip.get("listen_addr", "0.0.0.0"),
            "transport": sip.get("transport", "udp"),
            "udp_port": 5060,       # inside container; host maps ports["sip_udp"]
            "tls_port": 5061,
            "external": sip.get("external", []),
            "advertise_address": advertise_address(settings),
            # Outbound ring timeout: per-line override (sip.ring_timeout) wins, else the global
            # settings default, else 35s. Clamped to a sane 5..180 range.
            "ring_timeout": max(5, min(180, int(
                sip.get("ring_timeout") or settings.get("ring_timeout", 35)))),
            "user_agent": sip.get("user_agent", "iOS/26.6 iPhone"),
            # P-Access-Network-Info: composed from sip.pani_* options (or raw sip.pani override).
            # Default = IEEE-802.11;country=<SIM MCC country> — matches real VoWiFi UEs.
            "pani": build_pani(inst, sip),
            # Pass structured knobs through so a hand-re-rendered engine can rebuild without
            # re-running control (engine/render.py has a lightweight fallback).
            "pani_country_enable": _sip_bool(sip, "pani_country_enable", True),
            "pani_country": normalize_pani_country(sip.get("pani_country")),
            "pani_node_id_enable": _sip_bool(sip, "pani_node_id_enable", False),
            "pani_node_id": normalize_pani_node_id(sip.get("pani_node_id")),
            "pani_access_type": normalize_pani_access_type(sip.get("pani_access_type")),
            "pani_local_time_zone": (sip.get("pani_local_time_zone") or "").strip(),
            "webrtc": {
                "enable": bool(webrtc.get("enable", True)),
                "username": webrtc.get("username", "webrtc"),
                "password": webrtc.get("password") or "webrtc-secret",
                "port": 8089,
            },
        },
        "debug": inst.get("debug", settings.get("debug", {})),
        # Proactive CHILD-SA rekey period in minutes (0 = disabled). Per-line override
        # (inst.rekey_minutes) wins, else the global settings default, else 30. Clamped to 0
        # (off) or a sane 1..1440 window so a typo can't set an absurd sub-minute rekey storm.
        "rekey_minutes": _clamp_rekey(inst.get("rekey_minutes",
                                               (settings.get("rekey", {}) or {}).get("minutes", 30))),
        # APN + ePDG-identity (IDr) encoding for the SWu tunnel. apn defaults to the standard IMS
        # APN 'ims'; idr_mode defaults to 'apn' (the bare-APN form most carriers' ePDGs expect and
        # the proven-safe default) and may be set to 'fqdn' for the stricter ePDGs that require the
        # operator APN-FQDN. See swu_ike.py (SWU_APN / SWU_IDR_MODE).
        "apn": normalize_apn(inst.get("apn", "")),
        "idr_mode": normalize_idr_mode(inst.get("idr_mode", "")),
        # SWu CFG request address family (must match the carrier's IMS PDN). Defaults to 'auto'
        # (discovery ladder + carrier DB); 'v6' Telus/EE, 'v4' Vodafone UK, 'dual' both. When auto,
        # cp_mode_order gives the engine the discovery ladder (carrier-DB preference first).
        # See swu_ike.py (SWU_CP_MODE / SWU_CP_MODE_ORDER).
        "cp_mode": normalize_cp_mode(inst.get("cp_mode", "")),
        "cp_mode_order": cp_mode_order_for(inst["mcc"], inst["mnc"]),
        # EAP-AKA fast re-authentication (RFC 4187 AT_NEXT_REAUTH_ID). Default True: present the
        # AAA-issued re-auth identity as the IKEv2 IDi on a reconnect, with an automatic fallback
        # to the permanent NAI when the ePDG rejects it. Set False per line for a carrier whose
        # AAA reliably expires them (O2 UK), to skip the wasted attach round trip.
        "use_reauth_id": bool(inst.get("use_reauth_id", True)),
    }


def write_instance_json(inst: dict, settings: dict) -> str:
    d = os.path.join(DATA_DIR, "instances", str(inst["id"]))
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "instance.json")
    payload = json.dumps(render_instance_json(inst, settings), indent=2)
    # The engine bind-mounts this file (or its parent dir). os.replace() swaps
    # the inode; a running container keeps the old one and Asterisk never sees
    # new SIP accounts. Truncate-and-write the existing inode instead.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.ftruncate(fd, 0)
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return path
