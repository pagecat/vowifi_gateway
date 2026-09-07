"""
userbot.py - the control plane's window into the userbot call sidecar.

The userbot runs in its own container with its own dependencies and its own
Telegram session, deliberately not sharing the manager's settings. The one thing
the two do share is the data directory: the sidecar mounts <data>/userbot at
/data/userbot and already looks for its config there, so the WebUI can configure
it by writing a file rather than by talking to the container.

Status flows back the same way. The sidecar rewrites status.json every few
seconds; a timestamp older than STALE_AFTER means the container is not running,
which is the only "is it alive" signal we need and costs no cross-container call.

Lifecycle goes through the Docker socket the manager already holds, so the
container is the manager's to create rather than something the user runs by hand.
Starting is a recreate, as with engine containers: config and session both live on
the volume, so nothing is lost and one code path covers start, restart and
"apply the settings I just saved".
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time

import docker

from . import config as cfg
from . import engine

log = logging.getLogger("vowifi.userbot")

try:
    from telethon import TelegramClient
    from telethon.errors import (
        FloodWaitError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )
except ImportError:  # pragma: no cover - venv before `install.sh reload`
    TelegramClient = None

    class FloodWaitError(Exception):
        seconds = 0

    class PhoneCodeExpiredError(Exception):
        pass

    class PhoneCodeInvalidError(Exception):
        pass

    class SessionPasswordNeededError(Exception):
        pass

CONTAINER = "vowifi-userbot"
IMAGE = os.environ.get("VOWIFI_USERBOT_IMAGE", "vowifi/userbot")


class NotReady(Exception):
    """A precondition the user has to fix before the container can run."""

# Anything older than this and we call the sidecar offline. Comfortably above the
# sidecar's own write interval so a slow board doesn't look dead.
STALE_AFTER = 30
LOGIN_TTL = 600
BUILD_LOG_LIMIT = 200_000

_build_lock = threading.Lock()
_build_thread: threading.Thread | None = None

SIP_USER_DEFAULT = "tgbridge"

DEFAULTS = {
    "api_id": 0,
    "api_hash": "",
    "phone": "",
    # Inside the container. Telethon appends .session; the file grants full
    # control of the account, which is why it lives on the mounted volume.
    "session_name": "/data/userbot/userbot",
    # The primary account: the one a card answers for unless told otherwise,
    # and the identity the sidecar refuses to start without.
    "owner_id": 0,
    # Everyone ELSE allowed to drive it, primary excluded. Permissions are flat:
    # any of these may dial on any card.
    "owner_ids": [],
    "gateway_url": "https://127.0.0.1:8443",
    "gateway_verify_tls": False,
    # One entry per SIM the sidecar answers for:
    #   {"line": "1", "sip_user": "tgbridge", "answer_owner": 0}
    # answer_owner 0 means the primary account. A blank line resolves to the
    # first configured one on the next Start.
    "cards": [],
    "dial_allowlist": [],
    # Single-card keys from before multi-card. Read for migration and still
    # honoured in a hand-written config.json; never written back.
    "sip_user": "",
    "sip_password": "",     # blank = take it from the line's external account
    "sip_line": "",
}


def _dir() -> str:
    return os.path.join(cfg.DATA_DIR, "userbot")


def config_path() -> str:
    return os.path.join(_dir(), "config.json")


def status_path() -> str:
    return os.path.join(_dir(), "status.json")


def _login_path() -> str:
    return os.path.join(_dir(), "login_state.json")


def _build_path() -> str:
    return os.path.join(_dir(), "build.json")


def _host_session() -> str:
    """Telethon session path on THIS process's filesystem (no .session suffix)."""
    os.makedirs(_dir(), exist_ok=True)
    return os.path.join(_dir(), "userbot")


def _int_or_zero(value) -> int:
    try:
        return int(str(value).strip() or 0)
    except (TypeError, ValueError):
        return 0


def normalize_cards(conf: dict) -> list[dict]:
    """The configured cards, cleaned up and de-duplicated by line.

    A config written before multi-card carried one sip_line/sip_user pair
    instead. Folding that into a single card keeps the username Asterisk
    already has an endpoint for — renaming it would break a working line.
    """
    cards: list[dict] = []
    seen: set[str] = set()
    for raw in (conf.get("cards") or []):
        if not isinstance(raw, dict):
            continue
        line = str(raw.get("line") or "").strip()
        if line in seen:
            continue
        seen.add(line)
        cards.append({
            "line": line,
            "sip_user": str(raw.get("sip_user") or "").strip(),
            "answer_owner": _int_or_zero(raw.get("answer_owner")),
        })
    if cards:
        return cards
    legacy_line = str(conf.get("sip_line") or "").strip()
    legacy_user = str(conf.get("sip_user") or "").strip()
    if legacy_line or legacy_user:
        return [{"line": legacy_line,
                 "sip_user": legacy_user or SIP_USER_DEFAULT,
                 "answer_owner": 0}]
    return []


def authorized_ids(conf: dict) -> list[int]:
    """Every Telegram account allowed to drive the sidecar, primary first."""
    out: list[int] = []
    for raw in [conf.get("owner_id")] + list(conf.get("owner_ids") or []):
        uid = _int_or_zero(raw)
        if uid and uid not in out:
            out.append(uid)
    return out


def load() -> dict:
    out = dict(DEFAULTS)
    try:
        with open(config_path(), encoding="utf-8") as f:
            saved = json.load(f) or {}
        out.update({k: v for k, v in saved.items() if not k.startswith("_")})
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa
        log.warning("unreadable userbot config: %r", e)
    # Present one shape to every caller, whatever the file happens to hold.
    out["cards"] = normalize_cards(out)
    out["owner_ids"] = [uid for uid in authorized_ids(out)[1:]]
    return out


def public() -> dict:
    """For the WebUI: the api_hash is a credential for a whole Telegram account,
    so report only whether one is set. An empty one on save means unchanged,
    the same rule the bot token and the SIM PIN follow."""
    out = load()
    out["api_hash_set"] = bool((out.get("api_hash") or "").strip())
    out["sip_password_set"] = bool((out.get("sip_password") or "").strip())
    out["api_hash"] = ""
    out["sip_password"] = ""
    out["config_path"] = config_path()
    return out


def _clean_ids(raw) -> list[int]:
    """A comma-separated string or a list, either way a list of user ids."""
    if isinstance(raw, str):
        raw = raw.replace(";", ",").split(",")
    out: list[int] = []
    for item in (raw or []):
        text = str(item).strip()
        if not text:
            continue
        try:
            uid = int(text)
        except ValueError:
            raise ValueError(f"{text!r} is not a Telegram user ID — those are numbers "
                             "(ask @userinfobot)") from None
        if uid and uid not in out:
            out.append(uid)
    return out


def _clean_cards(raw, owners: list[int]) -> list[dict]:
    """Validate the card list the WebUI sent.

    SIP usernames have to be unique across every line, not just within one: the
    sidecar holds all of them in a single PJSUA2 endpoint, where two accounts
    sharing a `sip:user@host` identity make an inbound call ambiguous.
    """
    if not isinstance(raw, list):
        raise ValueError("cards must be a list")
    cards: list[dict] = []
    lines_seen: set[str] = set()
    users_seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        line = str(item.get("line") or "").strip()
        user = str(item.get("sip_user") or "").strip()
        owner = _int_or_zero(item.get("answer_owner"))
        if line and not cfg.get_instance(line):
            raise ValueError(f"there is no line {line}")
        if line in lines_seen:
            raise ValueError(f"line {line or '(first configured)'} is listed twice — "
                             "one card per line")
        lines_seen.add(line)
        if user:
            cfg.validate_sip_username(user)
            if user in users_seen:
                raise ValueError(f"two cards both use the SIP username {user!r} — "
                                 "each line needs its own")
            users_seen.add(user)
            clash = cfg.sip_username_line(user, exclude_iid=line)
            if clash:
                raise ValueError(f"SIP username {user!r} already belongs to line {clash} — "
                                 "each line needs its own")
        if owner and owner not in owners:
            raise ValueError(f"{owner} answers a card but is not an authorised account")
        cards.append({"line": line, "sip_user": user, "answer_owner": owner})
    return cards


def update(patch: dict) -> dict:
    current = load()
    patch = {k: v for k, v in (patch or {}).items()
             if k in DEFAULTS and not k.startswith("_")}
    if not str(patch.get("api_hash") or "").strip():
        patch.pop("api_hash", None)          # blank means keep
    if not str(patch.get("sip_password") or "").strip():
        patch.pop("sip_password", None)
    for key in ("api_id", "owner_id"):
        if key in patch:
            try:
                patch[key] = int(str(patch[key]).strip() or 0)
            except ValueError:
                raise ValueError(f"{key} must be a number")
    if "owner_ids" in patch:
        patch["owner_ids"] = _clean_ids(patch["owner_ids"])
    if "dial_allowlist" in patch:
        raw = patch["dial_allowlist"]
        if isinstance(raw, str):
            raw = raw.split(",")
        patch["dial_allowlist"] = [str(n).strip() for n in (raw or []) if str(n).strip()]

    merged = {**current, **patch}
    # The primary is never also an extra, and a card may only be answered by an
    # account that still exists after this save.
    merged["owner_ids"] = authorized_ids(merged)[1:]
    merged["cards"] = (_clean_cards(patch["cards"], authorized_ids(merged))
                       if "cards" in patch else normalize_cards(merged))
    if merged["cards"]:
        # Folded into cards; leaving them behind is a second source of truth.
        merged["sip_line"] = ""
        merged["sip_user"] = ""
    os.makedirs(_dir(), exist_ok=True)
    tmp = config_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
    os.replace(tmp, config_path())
    # The sidecar re-reads only at startup, so say so rather than let the user
    # wonder why nothing changed.
    log.info("userbot config written to %s", config_path())
    return public()


def status() -> dict:
    """What the sidecar last reported. `running` is derived from the timestamp:
    the sidecar has no way to tell us it died, so silence is the signal."""
    try:
        with open(status_path(), encoding="utf-8") as f:
            st = json.load(f) or {}
    except FileNotFoundError:
        return {"running": False, "reason": "the userbot container has never started"}
    except Exception as e:  # noqa
        return {"running": False, "reason": f"unreadable status file: {e}"}
    age = time.time() - float(st.get("ts") or 0)
    st["age"] = int(age)
    st["running"] = age < STALE_AFTER
    if not st["running"]:
        st["reason"] = f"no report for {int(age)}s — the container is probably stopped"
    return st


# ----------------------------- the container -----------------------------

def session_file() -> str | None:
    """Where Telethon's cached login lives on our side of the mount, or None if
    session_name was pointed somewhere we cannot see."""
    name = str(load().get("session_name") or "")
    prefix = "/data/userbot/"
    if not name.startswith(prefix):
        return None
    return os.path.join(_dir(), name[len(prefix):] + ".session")


def _authorized_path() -> str:
    return os.path.join(_dir(), "authorized")


def _mark_authorized(ok: bool) -> None:
    """Telethon writes .session as soon as it connects to send a login code.
    That file is not a completed login — only this marker is."""
    os.makedirs(_dir(), exist_ok=True)
    path = _authorized_path()
    if ok:
        with open(path, "w", encoding="utf-8") as f:
            f.write("1\n")
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def signed_in() -> bool:
    """True only after a completed sign-in. A .session file from send_code is
    not enough; treating it as signed-in hid the WebUI code box and started
    the sidecar, which then crash-looped on input()."""
    if os.path.isfile(_authorized_path()):
        return True
    login = _read_login()
    if login.get("phone_code_hash") or login.get("need_password"):
        return False
    path = session_file()
    if not (path and os.path.exists(path) and os.path.getsize(path) > 0):
        return False
    if TelegramClient is None:
        return False
    conf = load()

    async def _check(client):
        return bool(await client.is_user_authorized())

    try:
        ok = bool(_tg_run(_with_client(conf, _check)))
    except Exception:
        return False
    if ok:
        _mark_authorized(True)
    return ok


def snapshot() -> dict:
    login = _read_login()
    signed = signed_in()
    return {
        "config": public(),
        "status": status(),
        "container": container(),
        "signed_in": signed,
        "image_present": image_present(),
        "build": build_status(),
        "login": {
            "pending": bool(login.get("phone_code_hash")),
            "need_password": bool(login.get("need_password")),
            "phone": login.get("phone") or "",
        },
    }


# ----------------------------- Telegram login (WebUI) -----------------------------

def _read_login() -> dict:
    try:
        with open(_login_path(), encoding="utf-8") as f:
            st = json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    if time.time() - float(st.get("ts") or 0) > LOGIN_TTL:
        _clear_login()
        return {}
    return st


def _write_login(st: dict):
    os.makedirs(_dir(), exist_ok=True)
    tmp = _login_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, _login_path())


def _clear_login():
    try:
        os.remove(_login_path())
    except FileNotFoundError:
        pass


def _tg_run(coro):
    return asyncio.run(coro)


async def _with_client(conf: dict, fn):
    if TelegramClient is None:
        raise NotReady("telethon is not installed in the control plane — "
                       "on the gateway: sudo ./install.sh reload")
    api_id = int(conf.get("api_id") or 0)
    api_hash = str(conf.get("api_hash") or "").strip()
    if not api_id or not api_hash:
        raise NotReady("API ID and API hash are required to log in")
    client = TelegramClient(_host_session(), api_id, api_hash)
    await client.connect()
    try:
        return await fn(client)
    finally:
        await client.disconnect()


def send_login_code(force: bool = False) -> dict:
    """Ask Telegram to SMS the login code. Stops the sidecar first so it cannot
    hold the session file open."""
    if container().get("state") == "running":
        stop_container()
    conf = load()
    phone = str(conf.get("phone") or "").strip()
    if not phone:
        raise NotReady("the account phone number is empty")
    existing = _read_login()
    if (not force and existing.get("phone_code_hash")
            and existing.get("phone") == phone
            and time.time() - float(existing.get("ts") or 0) < 45):
        return {"ok": True, "phone": phone, "resent": False}

    async def _send(client):
        sent = await client.send_code_request(phone)
        return sent.phone_code_hash

    try:
        phone_code_hash = _tg_run(_with_client(conf, _send))
    except FloodWaitError as e:
        wait = int(getattr(e, "seconds", 0) or 0)
        raise NotReady(f"Telegram asked us to wait {wait}s before sending another code") from e
    except NotReady:
        raise
    except Exception as e:
        raise NotReady(f"could not send the login code: {e}") from e
    _write_login({"phone": phone, "phone_code_hash": phone_code_hash,
                  "need_password": False, "ts": time.time()})
    _mark_authorized(False)
    log.info("userbot login code sent to %s", phone)
    return {"ok": True, "phone": phone, "resent": True}


def confirm_login(code: str = "", password: str = "") -> dict:
    """Complete the login. `code` is the SMS; `password` is 2FA if Telegram asks."""
    conf = load()
    st = _read_login()
    phone = st.get("phone") or str(conf.get("phone") or "").strip()
    if not phone:
        raise NotReady("send a login code first")

    async def _sign(client):
        if password:
            await client.sign_in(password=password)
            return "ok"
        if not code:
            raise NotReady("enter the login code Telegram sent")
        hash_ = st.get("phone_code_hash") or ""
        await client.sign_in(phone, code, phone_code_hash=hash_)
        return "ok"

    try:
        _tg_run(_with_client(conf, _sign))
    except SessionPasswordNeededError:
        st["need_password"] = True
        st["ts"] = time.time()
        _write_login(st)
        return {"ok": False, "need_password": True}
    except PhoneCodeInvalidError as e:
        raise NotReady("that login code was rejected") from e
    except PhoneCodeExpiredError as e:
        _clear_login()
        raise NotReady("that login code expired — press Start to send a new one") from e
    except FloodWaitError as e:
        wait = int(getattr(e, "seconds", 0) or 0)
        raise NotReady(f"Telegram asked us to wait {wait}s") from e
    except NotReady:
        raise
    except Exception as e:
        raise NotReady(f"login failed: {e}") from e
    _clear_login()
    _mark_authorized(True)
    log.info("userbot Telegram session saved under %s", _dir())
    return {"ok": True, "signed_in": True}


# ----------------------------- image build -----------------------------

def repo_dir() -> str:
    env = (os.environ.get("VOWIFI_REPO") or "").strip()
    if env and os.path.isfile(os.path.join(env, "userbot", "Dockerfile")):
        return env
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if os.path.isfile(os.path.join(here, "userbot", "Dockerfile")):
        return here
    raise NotReady("cannot find userbot/Dockerfile. Set VOWIFI_REPO to the repo root, "
                   "or on the gateway: sudo ./install.sh reload")


def image_present() -> bool:
    try:
        engine.client().images.get(IMAGE)
        return True
    except docker.errors.ImageNotFound:
        return False
    except docker.errors.DockerException:
        engine.reset_client()
        return False


def build_status() -> dict:
    try:
        with open(_build_path(), encoding="utf-8") as f:
            st = json.load(f) or {}
    except FileNotFoundError:
        st = {}
    except Exception:
        st = {}
    st.setdefault("running", False)
    st.setdefault("log", "")
    st.setdefault("ok", image_present() if not st.get("running") else False)
    st["image_present"] = image_present()
    return st


def _write_build(st: dict):
    os.makedirs(_dir(), exist_ok=True)
    log_text = st.get("log") or ""
    if len(log_text) > BUILD_LOG_LIMIT:
        st["log"] = log_text[-BUILD_LOG_LIMIT:]
    tmp = _build_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    last = None
    for _ in range(8):
        try:
            os.replace(tmp, _build_path())
            return
        except PermissionError as e:
            last = e
            time.sleep(0.05)
    if last:
        raise last


def start_build() -> dict:
    global _build_thread
    with _build_lock:
        st = build_status()
        if st.get("running"):
            return st
        repo = repo_dir()
        st = {"running": True, "ok": False,
              "log": f"building {IMAGE} from {repo} (docker network=host)\n",
              "started": time.time()}
        _write_build(st)
        _build_thread = threading.Thread(target=_run_build, args=(repo,), daemon=True)
        _build_thread.start()
    return build_status()


def _run_build(repo: str):
    st = build_status()
    # A dedicated client: the shared engine client is polled every few seconds
    # for image_present(), and a 60s default timeout would abort a quiet PJSIP
    # compile. Host network: docker bridge on this class of host often cannot
    # reach the internet (apt hangs on deb.debian.org) while the host itself can.
    build_client = None
    try:
        build_client = docker.from_env(timeout=None)
        gen = build_client.api.build(
            path=repo, dockerfile="userbot/Dockerfile", tag=IMAGE,
            rm=True, decode=True, network_mode="host",
        )
        for chunk in gen:
            if not isinstance(chunk, dict):
                continue
            line = chunk.get("stream") or chunk.get("status") or ""
            if chunk.get("error"):
                line = chunk["error"]
            if line:
                st["log"] = (st.get("log") or "") + line
                if not line.endswith("\n"):
                    st["log"] += "\n"
                _write_build(st)
            if chunk.get("error"):
                raise RuntimeError(chunk["error"])
        st["running"] = False
        st["ok"] = image_present()
        if not st["ok"]:
            st["log"] = (st.get("log") or "") + "build finished but the image is still missing\n"
        _write_build(st)
        log.info("userbot image build %s", "ok" if st["ok"] else "failed")
    except Exception as e:  # noqa
        st["running"] = False
        st["ok"] = False
        st["log"] = (st.get("log") or "") + f"build failed: {e}\n"
        _write_build(st)
        log.warning("userbot image build failed: %s", e)
    finally:
        if build_client is not None:
            try:
                build_client.close()
            except Exception:
                pass


# ----------------------------- SIP account -----------------------------

def _require_start_fields(conf: dict):
    """Fail before a 20-minute image build, not after."""
    missing = []
    if not int(conf.get("api_id") or 0):
        missing.append("API ID")
    if not str(conf.get("api_hash") or "").strip():
        missing.append("API hash")
    if not str(conf.get("phone") or "").strip():
        missing.append("account phone number")
    if not int(conf.get("owner_id") or 0):
        missing.append("your Telegram user ID")
    if missing:
        raise NotReady("fill in " + ", ".join(missing) + " first")
    phone = str(conf.get("phone") or "").strip()
    if not phone.startswith("+"):
        raise NotReady("the account phone number must be in international form, starting with +")


def _derive_sip_user(iid: str, taken: set[str]) -> str:
    """A username no other line is using. The first card keeps the historical
    plain `tgbridge` so an install that already works is not renamed out from
    under a live Asterisk endpoint."""
    for candidate in [SIP_USER_DEFAULT, f"{SIP_USER_DEFAULT}{iid}"]:
        if candidate not in taken and not cfg.sip_username_line(candidate, exclude_iid=iid):
            return candidate
    suffix = 2
    while True:
        candidate = f"{SIP_USER_DEFAULT}{iid}-{suffix}"
        if candidate not in taken and not cfg.sip_username_line(candidate, exclude_iid=iid):
            return candidate
        suffix += 1


def ensure_sip_accounts(conf: dict) -> list[str]:
    """Give every configured card a SIP account on its line, creating what is
    missing. A running engine is re-rendered and PJSIP reloaded so the sidecar
    can register without a full line restart.

    Returns one note per card that needed saying; the WebUI shows them.
    """
    instances = cfg.list_instances()
    if not instances:
        raise NotReady("no SIM line is configured yet — add one under SIM Config first")
    cards = normalize_cards(conf)
    if not cards:
        cards = [{"line": "", "sip_user": "", "answer_owner": 0}]

    notes: list[str] = []
    resolved: list[dict] = []
    taken = {c["sip_user"] for c in cards if c.get("sip_user")}
    for card in cards:
        wanted = str(card.get("line") or "").strip()
        inst = cfg.get_instance(wanted) if wanted else instances[0]
        if not inst:
            raise NotReady(f"no line {wanted}")
        iid = str(inst["id"])
        user = str(card.get("sip_user") or "").strip() or _derive_sip_user(iid, taken)
        taken.add(user)
        resolved.append({**card, "line": iid, "sip_user": user})

        sip = dict(inst.get("sip") or {})
        external = [a for a in (sip.get("external") or []) if isinstance(a, dict)]
        created = False
        if not any(str(a.get("username") or "").strip() == user for a in external):
            password = str(card.get("sip_password") or "").strip() or secrets.token_urlsafe(12)
            external.append({"username": user, "password": password})
            try:
                inst = cfg.upsert_instance({"id": iid, "sip": {**sip, "external": external}})
            except ValueError as e:
                raise NotReady(str(e)) from e
            created = True
        # The account may already be in config.yaml from an earlier Start that
        # never reached a live Asterisk reload. Always re-render a running engine.
        if engine.is_running(iid):
            settings = (cfg.load() or {}).get("settings") or {}
            cfg.write_instance_json(inst, settings)
            result = engine.rerender(iid, expect_user=user)
            if result != "ok":
                log.warning("userbot: SIP account %s on line %s reload said %s",
                            user, iid, result)
                notes.append(f"{'created' if created else 'found'} SIP account {user} on "
                             f"line {iid}, but the running engine did not reload ({result}) "
                             f"— Stop → Start that line")
                continue
        if created:
            log.info("created external SIP account %s on line %s", user, iid)
            notes.append(f"created SIP account {user} on line {iid}")

    # Persist whatever we had to fill in (a blank line, a derived username) so
    # the sidecar reads the same cards the engines were just configured for.
    if resolved != cards:
        update({"cards": resolved})
        conf["cards"] = resolved
    return notes


def prepare_and_start(body: dict | None = None) -> dict:
    """One WebUI action: save, ensure SIP, build image, log in, start."""
    body = dict(body or {})
    code = str(body.pop("login_code", "") or "").strip()
    password = str(body.pop("login_password", "") or "").strip()
    resend = bool(body.pop("resend_code", False))
    if body:
        try:
            update(body)
        except ValueError as e:
            raise NotReady(str(e)) from e
    conf = load()
    _require_start_fields(conf)
    notes = ensure_sip_accounts(conf)

    if not image_present():
        start_build()
        return {**snapshot(), "ok": False, "phase": "building", "notes": notes}
    if build_status().get("running"):
        return {**snapshot(), "ok": False, "phase": "building", "notes": notes}

    pending = _read_login()
    if ((code and pending.get("phone_code_hash"))
            or (password and pending.get("need_password"))):
        result = confirm_login(code=code, password=password)
        if result.get("need_password"):
            return {**snapshot(), "ok": False, "phase": "password", "notes": notes}

    if not signed_in():
        send_login_code(force=resend)
        return {**snapshot(), "ok": False, "phase": "login", "notes": notes}

    start_container()
    return {**snapshot(), "ok": True, "phase": "running", "notes": notes}


def _clear_status():
    """Drop the last heartbeat. Restart would otherwise keep showing the previous
    process as healthy until STALE_AFTER, because the file lives on the volume."""
    try:
        os.remove(status_path())
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa
        log.debug("could not clear userbot status: %s", e)


def _sync_gateway_url(conf: dict) -> dict:
    """Host-network sidecar talks to the manager on loopback. Follow the live
    HTTPS port so a Settings change off 8443 does not leave it calling the old one.
    A non-loopback URL is left alone — that was a deliberate override."""
    port = int((cfg.load() or {}).get("http_port") or 8443)
    live = f"https://127.0.0.1:{port}"
    url = (conf.get("gateway_url") or "").strip().rstrip("/")
    if not url or url.startswith("https://127.0.0.1:") or url.startswith("http://127.0.0.1:"):
        if url != live:
            update({"gateway_url": live})
            return load()
    return conf


def container() -> dict:
    """Docker's view, which answers a different question from status(): the
    container can be up while the sidecar inside it is failing to sign in."""
    try:
        c = engine.client().containers.get(CONTAINER)
    except docker.errors.NotFound:
        return {"exists": False, "state": "absent"}
    except docker.errors.DockerException as e:  # noqa
        engine.reset_client()
        return {"exists": False, "state": "unknown", "error": str(e)}
    return {"exists": True, "state": c.status, "started_at": c.attrs.get("State", {}).get("StartedAt")}


def start_container() -> str:
    """Recreate and start it. Raises NotReady with something the user can act on."""
    conf = load()
    missing = [k for k in ("api_id", "api_hash", "owner_id") if not conf.get(k)]
    if missing:
        raise NotReady(f"the userbot is not configured yet — {', '.join(missing)} still empty")
    host_dir = os.path.join(engine.HOST_DATA_DIR, "userbot")
    if not signed_in():
        raise NotReady("this Telegram account has not logged in yet — "
                       "press Start and enter the code Telegram sends")

    client = engine.client()
    # Probe the image BEFORE tearing the old container down. Restarting when the
    # image is gone used to leave the user with nothing running.
    try:
        client.images.get(IMAGE)
    except docker.errors.ImageNotFound:
        raise NotReady(f"the {IMAGE} image is not built yet — press Start to build it") from None

    conf = _sync_gateway_url(conf)
    os.makedirs(_dir(), exist_ok=True)
    try:
        old = client.containers.get(CONTAINER)
        old.remove(force=True)
    except docker.errors.NotFound:
        pass
    _clear_status()

    volumes = {host_dir: {"bind": "/data/userbot", "mode": "rw"}}
    # Match the host clock. The sidecar timestamps its own log and the call
    # summaries it sends the owner, and a container that quietly runs on UTC
    # makes both of those read as somebody else's day.
    if os.path.exists("/etc/localtime"):
        volumes["/etc/localtime"] = {"bind": "/etc/localtime", "mode": "ro"}

    c = client.containers.run(
        IMAGE,
        name=CONTAINER,
        detach=True,
        # The SIP leg registers to the engine's port on the host and receives RTP
        # on whatever port PJSIP picks, so published ports are not workable.
        network_mode="host",
        volumes=volumes,
        restart_policy={"Name": "unless-stopped"},
    )
    log.info("started userbot container %s", c.name)
    return c.id


def stop_container() -> bool:
    try:
        engine.client().containers.get(CONTAINER).remove(force=True)
        _clear_status()
        return True
    except docker.errors.NotFound:
        _clear_status()
        return False


def logs(tail: int = 200) -> str:
    try:
        return engine.client().containers.get(CONTAINER).logs(tail=tail).decode(errors="replace")
    except docker.errors.NotFound:
        return ""
    except Exception as e:  # noqa
        return f"error: {e}"
