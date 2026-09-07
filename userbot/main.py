"""
main.py - the userbot sidecar entry point.

Runs a Telegram user account (not a bot account - bot accounts cannot be in a
voice call) that bridges Telegram calls to a SIM line, and takes /call, /dtmf
and /hangup from its owner over the same account's private chat.

Commands are deliberately re-checked here rather than trusted from the main bot:
this process can dial arbitrary numbers, so it enforces its own owner check and
its own dial allow-list. Being a separate container from the control plane is
part of that - it keeps the native ntgcalls and PJSIP dependencies, and their
crash surface, away from the gateway.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

import requests
from telethon import TelegramClient, events

from bridge import CallBridge
from sip_leg import SipLeg, shutdown_endpoint
from telegram_call import TelegramCallLeg

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("userbot")

HELP = """VoWiFi userbot

/call <number> [line] - I ring you, you answer, then I dial the number
/use <line> - pick the card /call uses from now on
/lines - list my cards and which of us answers each
/dtmf <digits> - send tones during a call (e.g. /dtmf 1234)
/hangup - end the current call

Calls to a SIM are bridged to whoever answers that card.

I only do calls. SMS, line control and eSIM belong to the gateway bot, in its
own chat — including its own /use and /lines, which pick the line those
commands act on rather than the SIM I dial from."""

SIP_USER_DEFAULT = "tgbridge"

# Commands the gateway's notification bot owns. It is a different account in a
# different chat, so one of these turning up here means the wrong window, which
# is worth saying instead of ignoring. Mirrors _USERBOT_COMMANDS in
# control/app/telegram_bot.py: this container ships without the control plane's
# code, so the two lists cannot share an import.
GATEWAY_COMMANDS = (
    "/status", "/sms", "/msgs", "/pin",
    "/line_start", "/line_stop", "/line_register", "/line_reprovision",
    "/esim", "/esim_profiles", "/esim_enable", "/esim_disable", "/esim_delete",
    "/esim_download", "/esim_notify", "/esim_notify_process",
)


def load_config() -> dict:
    for path in (Path(__file__).parent / "config.json", Path("/data/userbot/config.json")):
        if path.exists():
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    log.error("no config.json (looked next to main.py and in /data/userbot)")
    sys.exit(1)


def normalize_cards(cfg: dict) -> list[dict]:
    """One entry per SIM we answer for. The control plane writes this list, but
    a hand-written config (and anything from before multi-card) may still carry
    a single sip_line/sip_user pair instead."""
    cards = []
    for raw in (cfg.get("cards") or []):
        if not isinstance(raw, dict):
            continue
        cards.append({
            "line": str(raw.get("line") or "").strip(),
            "sip_user": str(raw.get("sip_user") or "").strip() or SIP_USER_DEFAULT,
            "answer_owner": int(raw.get("answer_owner") or 0),
            "sip_password": str(raw.get("sip_password") or "").strip(),
        })
    if cards:
        return cards
    return [{"line": str(cfg.get("sip_line") or "").strip(),
             "sip_user": str(cfg.get("sip_user") or "").strip() or SIP_USER_DEFAULT,
             "answer_owner": 0,
             "sip_password": str(cfg.get("sip_password") or "").strip()}]


def authorized_ids(cfg: dict) -> list[int]:
    """Everyone allowed to drive us, primary first. Flat permissions: any of
    them may dial on any card."""
    out = []
    for raw in [cfg.get("owner_id")] + list(cfg.get("owner_ids") or []):
        try:
            uid = int(str(raw).strip() or 0)
        except (TypeError, ValueError):
            continue
        if uid and uid not in out:
            out.append(uid)
    return out


def first_line(cfg: dict) -> str:
    base = cfg["gateway_url"].rstrip("/")
    verify = bool(cfg.get("gateway_verify_tls", False))
    r = requests.get(f"{base}/api/instances", timeout=10, verify=verify)
    r.raise_for_status()
    instances = r.json().get("instances", [])
    if not instances:
        raise RuntimeError("the gateway has no configured lines")
    return str(instances[0]["id"])


def sip_params(cfg: dict, card: dict) -> dict:
    """Ask the control plane where this card's line lives, what our own account's
    password on it is, and which number the SIM answers as. Read-only, and the
    only thing the sidecar needs from the gateway - calls are pure SIP."""
    base = cfg["gateway_url"].rstrip("/")
    verify = bool(cfg.get("gateway_verify_tls", False))
    line = str(card.get("line") or "") or first_line(cfg)
    r = requests.get(f"{base}/api/instances/{line}/sipinfo", timeout=10, verify=verify)
    r.raise_for_status()
    info = r.json()

    host = info.get("host") or info.get("domain") or "127.0.0.1"
    port = int(info.get("port") or 5060)
    if info.get("transport") == "tls":
        # The endpoint reports the TLS port for a TLS line, and registering to it
        # over UDP just times out. Fail loudly rather than mysteriously.
        raise RuntimeError(f"line {line} uses SIP/TLS; the userbot only speaks UDP so far")
    if not info.get("running"):
        log.warning("line %s is not running — SIP registration will fail until it is", line)

    # The gateway already knows our password: it is the external account the user
    # created in the WebUI. Taking it from here means one less secret to copy, and
    # it cannot go stale behind our back.
    user = card["sip_user"]
    accounts = {a.get("username"): a.get("password") for a in (info.get("accounts") or [])}
    if user not in accounts:
        raise RuntimeError(
            f"line {line} has no external SIP account called {user!r} "
            f"(it has: {', '.join(accounts) or 'none'}). Create one in the WebUI under "
            f"SIM Config -> External SIP accounts.")
    password = card.get("sip_password") or accounts[user] or ""
    if not password:
        raise RuntimeError(f"external SIP account {user!r} has no password set")

    log.info("line %s speaks SIP at %s:%s as %s", line, host, port, user)
    return {"line": line, "host": host, "port": port, "password": password,
            "msisdn": str(info.get("msisdn") or "").strip()}


class UserBot:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.owners = authorized_ids(cfg)
        if not self.owners:
            log.error("no owner_id configured — nobody would be allowed to use this")
            sys.exit(1)
        self.owner = self.owners[0]
        self.cards = normalize_cards(cfg)
        self.allow = [str(n).strip() for n in (cfg.get("dial_allowlist") or []) if str(n).strip()]
        self.client = TelegramClient(cfg["session_name"], cfg["api_id"], cfg["api_hash"])
        self.bridge: CallBridge | None = None
        self.legs: dict[str, SipLeg] = {}
        # Which card each account dials on, until they say /use. Sticky per
        # account, not global: two people should not fight over one selection.
        self.selected: dict[int, str] = {}
        self.last_error = ""

    # ---------- status ----------

    def _status_path(self) -> Path:
        """Next to the session, i.e. in the directory the control plane shares with
        us. It reads this file to show the sidecar in the WebUI."""
        return Path(self.cfg["session_name"]).parent / "status.json"

    async def _write_status(self):
        path = self._status_path()
        try:
            tg = self.bridge.tg if self.bridge else None
            cards = [{"line": line, "sip_user": leg.user, "registered": bool(leg.registered)}
                     for line, leg in self.legs.items()]
            payload = {
                "ts": int(time.time()),
                "telegram_connected": bool(self.client.is_connected()),
                # The WebUI pill reads this one: every card we manage to bring
                # up must be registered before we claim the SIP side is healthy.
                "sip_registered": bool(cards) and all(c["registered"] for c in cards),
                "in_call": bool(tg and tg.active),
                "owner_id": self.owner,
                "owner_ids": self.owners,
                "cards": cards,
                "sip_user": ", ".join(c["sip_user"] for c in cards),
                "last_error": self.last_error,
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(path)
        except Exception as e:  # noqa
            log.debug("status write failed: %s", e)

    async def _report_status(self):
        """Rewrite status.json on a timer. The control plane treats a stale
        timestamp as 'not running' — we have no way to announce our own death,
        so a heartbeat is the signal."""
        while True:
            await self._write_status()
            await asyncio.sleep(5)

    def _may_dial(self, number: str) -> bool:
        return not self.allow or number in self.allow

    async def run(self):
        # Never client.start(phone=): that calls input() for the login code, and a
        # detached container has no stdin (EOFError crash loop). Login happens in
        # the WebUI; we only accept an already-authorized session.
        await self.client.connect()
        if not await self.client.is_user_authorized():
            self.last_error = "not signed in — enter the login code in Settings"
            log.error("%s", self.last_error)
            await self._write_status()
            await asyncio.sleep(300)
            return
        me = await self.client.get_me()
        log.info("signed in as %s (id=%s)", me.first_name, me.id)

        heartbeat = asyncio.create_task(self._report_status())
        known: dict[str, dict] = {}
        failures: list[str] = []
        for card in self.cards:
            try:
                # sip_params is blocking HTTP. Run it off the loop so the heartbeat
                # can actually write last_error / "not yet registered" while we wait.
                found = await asyncio.to_thread(sip_params, self.cfg, card)
                line = found["line"]
            except Exception as e:  # noqa
                # Setup mistakes land here: no such external account, the line is
                # stopped, the line is TLS. One bad card must not cost us the
                # others, so record it and carry on.
                log.error("card %s: %s", card.get("line") or "(first line)", e)
                failures.append(f"line {card.get('line') or '?'}: {e}")
                continue
            if line in self.legs:
                # Two cards resolved to one line (a blank one plus its explicit
                # id, say). Keeping both would leave a leg nothing can reach.
                log.warning("line %s is configured twice — ignoring the %s card",
                            line, card["sip_user"])
                continue
            leg = SipLeg(card["sip_user"], found["password"], found["host"], found["port"])
            leg.start()
            self.legs[line] = leg
            known[line] = {"answerer": card.get("answer_owner") or self.owner,
                           "msisdn": found["msisdn"]}

        if not self.legs:
            # Publish why before backing off, or the WebUI shows a container that
            # is up and says nothing about what is wrong.
            self.last_error = "; ".join(failures) or "no cards are configured"
            await self._write_status()
            await asyncio.sleep(30)
            heartbeat.cancel()
            raise RuntimeError(self.last_error)
        self.last_error = "; ".join(failures)

        loop = asyncio.get_running_loop()
        tg = TelegramCallLeg(self.client, self.owners)
        tg.install(loop)
        self.bridge = CallBridge(tg, self.legs, known, loop)

        self.client.add_event_handler(self._on_message, events.NewMessage(incoming=True))
        log.info("userbot ready — cards %s, authorised %s",
                 ", ".join(self.legs) or "none",
                 ", ".join(str(o) for o in self.owners))
        try:
            await self.client.run_until_disconnected()
        finally:
            heartbeat.cancel()
            for leg in self.legs.values():
                leg.stop()
            shutdown_endpoint()

    def _card_for(self, who: int) -> str:
        """The card this account dials on: their own /use choice, else the first."""
        chosen = self.selected.get(who)
        if chosen in self.legs:
            return chosen
        return next(iter(self.legs), "")

    async def _on_message(self, event):
        # Only an authorised account, in its own private chat. Anyone else is
        # ignored without a reply, same as the control-plane bot.
        who = event.chat_id
        if who not in self.owners or not event.raw_text:
            return
        text = event.raw_text.strip()
        cmd, _, arg = text.partition(" ")
        cmd, arg = cmd.split("@", 1)[0].lower(), arg.strip()
        if cmd in GATEWAY_COMMANDS:
            await event.reply(f"{cmd} belongs to the gateway bot, not to me — send it in that "
                              f"chat. I only bridge calls: /call, /use, /lines, /dtmf, /hangup.")
            return
        if cmd not in ("/start", "/help", "/call", "/use", "/lines", "/dtmf", "/hangup"):
            # Anything else is somebody talking, not commanding. Stay quiet.
            return
        try:
            reply = await self._run_command(who, cmd, arg)
        except Exception as e:  # noqa
            # Telethon would swallow this into the container log, leaving the
            # caller staring at a command that answered nothing at all.
            log.exception("%s failed", cmd)
            reply = f"{cmd} failed: {type(e).__name__}: {e}"
        await event.reply(reply)

    async def _run_command(self, who: int, cmd: str, arg: str) -> str:
        if cmd in ("/start", "/help"):
            return HELP
        if cmd == "/lines":
            return (self.bridge.describe_lines()
                    + f"\n\nYou are dialling on line {self._card_for(who)}."
                    + "\n(These are my SIP cards. The gateway bot's /lines lists its lines.)")
        if cmd == "/use":
            line = arg.split()[0] if arg else ""
            if line not in self.legs:
                return f"Usage: /use <line>. I have: {', '.join(self.legs) or 'no cards'}."
            self.selected[who] = line
            return f"Your calls now go out on line {line}."
        if cmd == "/call":
            parts = arg.split()
            number = parts[0] if parts else ""
            if not number:
                return "Usage: /call <number> [line]"
            if not self._may_dial(number):
                return f"{number} is not in this userbot's dial allow-list."
            # A trailing line wins for this call only; it does not move /use.
            line = parts[1] if len(parts) > 1 else self._card_for(who)
            return await self.bridge.place_call(number, line, who)
        if cmd == "/dtmf":
            return self.bridge.send_dtmf(arg)
        return await self.bridge.hangup()


if __name__ == "__main__":
    asyncio.run(UserBot(load_config()).run())
