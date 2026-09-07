"""
telegram_bot.py - inbound Telegram control; the other half of notify_push.

notify_push already pushes outgoing notifications through a bot token. This module makes the
same bot listen, so SMS and line lifecycle can be driven from a Telegram chat.

Long polling rather than a webhook: the gateway normally sits on a LAN behind a self-signed
certificate, and getUpdates needs nothing but OUTBOUND HTTPS. The loop runs inside the manager
process and calls the FastAPI route handlers directly, so a command never traverses the
control plane's (unauthenticated) HTTP API.

Messages are sent as plain text on purpose — no parse_mode. SMS bodies and peer numbers are
attacker-controlled, and with Markdown or HTML enabled a crafted message could forge the bot's
own formatting. See notify_push for the same decision on the outbound side.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import OrderedDict

import requests
from fastapi import HTTPException

from . import config as cfg
from . import store
from . import userbot as userbot_cfg

log = logging.getLogger("vowifi.telegram")

_API = "https://api.telegram.org/bot{token}/{method}"
POLL_TIMEOUT = 25           # seconds Telegram holds getUpdates open with no traffic
_HTTP_TIMEOUT = POLL_TIMEOUT + 10
_IDLE_SLEEP = 5             # settings re-check cadence while the bot is disabled
_ERROR_SLEEP = 5
_CONFLICT_SLEEP = 30        # another poller/webhook owns this token; do not spin
# getUpdates replays every unconfirmed update for up to 24h. After a night of downtime that
# would re-execute yesterday's commands, so anything older than this is read and dropped.
_STALE_UPDATE_AGE = 60
_MAX_REPLY_TARGETS = 200
_MAX_TRACKED_SENDS = 200
_CONFIRM_TTL = 120
# How long a chat's eSIM reader/eUICC pick stays current. Long enough to run a few commands,
# short enough that a forgotten selection can't act on a card that has since been swapped.
_ESIM_TARGET_TTL = 600

_HELP = """VoWiFi gateway

/status - all lines and their state
/lines - configured lines
/use <line> - pick the line these commands act on
/sms <number> <text> - send an SMS
/msgs - recent conversations; /msgs <number> opens one
Reply to an incoming SMS to answer it.

Line control (if enabled):
/line_start <line>
/line_stop <line>
/line_register <line>
/line_reprovision <line>
/pin <line> <pin> - unlock and start

eSIM (if enabled):
/esim - pick the reader (and eUICC) to work on
/esim_profiles - list profiles on it
/esim_enable <iccid> - switch profile
/esim_disable <iccid>
/esim_delete <iccid> - permanent
/esim_download <activation code>
/esim_notify - pending notifications
/esim_notify_process <seq|all>

Calls (/call, /dtmf, /hangup) belong to the userbot account, not to me -
send those in its chat. My /use and /lines are about SMS and line control;
its own /use and /lines are about which SIM it dials on."""

# Commands the call sidecar owns. It is a separate Telegram account in its own
# chat, so the two never see each other's messages - which is exactly why one of
# them arriving here is worth answering rather than calling it unknown.
# userbot/main.py carries the mirror of this list; the sidecar ships without the
# control plane's code, so a shared import is not available to it.
_USERBOT_COMMANDS = ("/call", "/dtmf", "/hangup")

# Structured 409/400 codes the route handlers raise, in words a chat can act on.
_CODE_HELP = {
    "pin_required": "the SIM wants its PIN — send /pin <line> <pin>",
    "pin_invalid": "the saved PIN was rejected — send /pin <line> <pin> with the right one",
    "no_card": "no SIM card in that line's reader",
    "duplicate_iccid": "that SIM is already configured as another line",
    "duplicate_sip_username": "a SIP username collides with a reserved or existing one",
}


def _routes():
    """Late import of the route handlers. main imports this module to start the loop, so the
    reverse direction can only be resolved once, at call time."""
    from . import main
    return main


def _call(token: str, method: str, payload: dict | None = None, timeout: float = _HTTP_TIMEOUT):
    """One Bot API call. Returns (ok, result | error dict). Blocking — run it in a thread."""
    try:
        r = requests.post(_API.format(token=token, method=method),
                          json=payload or {}, timeout=timeout)
    except Exception as e:  # noqa
        return False, {"error": repr(e)}
    try:
        body = r.json()
    except Exception:  # noqa
        return False, {"error": f"HTTP {r.status_code}", "status": r.status_code}
    if r.status_code == 200 and body.get("ok"):
        return True, body.get("result")
    return False, {"error": body.get("description") or f"HTTP {r.status_code}",
                   "status": r.status_code,
                   "retry_after": (body.get("parameters") or {}).get("retry_after")}


def _cmd_and_args(text: str) -> tuple[str, str]:
    """Split '/sms@thebot +123 hi' into ('/sms', '+123 hi')."""
    head, _, rest = text.strip().partition(" ")
    cmd = head.split("@", 1)[0].lower()
    return cmd, rest.strip()


def _explain(e: Exception) -> str:
    """Turn a route handler's HTTPException into something worth reading in a chat."""
    if not isinstance(e, HTTPException):
        return str(e) or repr(e)
    detail = e.detail
    if isinstance(detail, dict):
        code = detail.get("code") or ""
        if code == "card_mismatch":
            return (f"the card in {detail.get('reader')} is a different SIM "
                    f"(ICCID {detail.get('card_iccid')}, this line expects "
                    f"{detail.get('line_iccid')}) — an eSIM profile switch looks like this")
        known = _CODE_HELP.get(code)
        if known:
            tries = detail.get("tries")
            return known + (f" ({tries} tries left)" if tries is not None else "")
        return detail.get("message") or code or str(detail)
    return str(detail)


class TelegramBot:
    """Long-poll loop plus command handling. One instance per manager process."""

    def __init__(self, hub):
        self.hub = hub
        self._offset: int | None = None
        self._token = ""
        self._chat_line: dict[str, str] = {}          # chat id -> the line it acts on
        # Telegram message id of an incoming-SMS notification -> the conversation it came from,
        # so a plain reply in the chat answers the right peer on the right line.
        self._reply_targets: OrderedDict[int, tuple[str, str]] = OrderedDict()
        # SMS row id -> (chat, message) of the "sending" line to rewrite once the network
        # confirms. Delivery is asynchronous: the send call only proves IMS accepted it.
        self._sent: OrderedDict[int, tuple[str, int]] = OrderedDict()
        self._pending: dict[str, dict] = {}           # confirm token -> queued action
        self._confirm_seq = 0
        # eSIM is addressed by READER, not by line, so it needs its own per-chat selection.
        self._esim_target: dict[str, dict] = {}       # chat -> {reader, index, se_id, aid, ts}
        self._typed: dict[str, dict] = {}             # chat -> a pending type-this-to-confirm
        self._downloads: dict[str, dict] = {}         # reader -> {chat, message_id, last_edit}
        self._unsubscribe = None

    # ---------------- Telegram plumbing ----------------

    async def _api(self, method: str, payload: dict, timeout: float = _HTTP_TIMEOUT):
        return await asyncio.to_thread(_call, self._token, method, payload, timeout)

    async def send(self, chat: str, text: str, reply_to: int | None = None,
                   keyboard: list | None = None) -> int | None:
        payload: dict = {"chat_id": chat, "text": text, "disable_web_page_preview": True}
        if reply_to:
            payload["reply_to_message_id"] = reply_to
            payload["allow_sending_without_reply"] = True
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        ok, res = await self._api("sendMessage", payload)
        if not ok:
            log.warning("sendMessage failed: %s", res.get("error"))
            return None
        return (res or {}).get("message_id")

    async def edit(self, chat: str, message_id: int, text: str):
        ok, res = await self._api("editMessageText",
                                  {"chat_id": chat, "message_id": message_id, "text": text,
                                   "disable_web_page_preview": True})
        if not ok:
            log.debug("editMessageText failed: %s", res.get("error"))

    async def delete(self, chat: str, message_id: int):
        await self._api("deleteMessage", {"chat_id": chat, "message_id": message_id})

    # ---------------- reply / delivery bookkeeping ----------------

    def remember_reply_target(self, message_id: int, iid: str, peer: str):
        """Called after an incoming-SMS notification goes out, so replying to it answers back."""
        if not message_id or not peer:
            return
        self._reply_targets[int(message_id)] = (str(iid), str(peer))
        while len(self._reply_targets) > _MAX_REPLY_TARGETS:
            self._reply_targets.popitem(last=False)

    def _track_send(self, row_id, chat: str, message_id: int | None):
        if not row_id or not message_id:
            return
        self._sent[int(row_id)] = (chat, int(message_id))
        while len(self._sent) > _MAX_TRACKED_SENDS:
            self._sent.popitem(last=False)

    async def on_event(self, msg: dict):
        """Hub subscriber. The send API only confirms that IMS accepted the message; the real
        verdict arrives later from the delivery watcher, so rewrite the original chat line.
        eSIM downloads report progress the same way."""
        if msg.get("type") == "esim_download":
            await self._on_download_event(msg)
            return
        if msg.get("type") != "sms":
            return
        rec = msg.get("message") or {}
        row = rec.get("id")
        if not row or int(row) not in self._sent:
            return
        status = rec.get("status")
        if status not in ("delivered", "failed"):
            return
        chat, message_id = self._sent.pop(int(row))
        peer = rec.get("peer") or ""
        if status == "delivered":
            await self.edit(chat, message_id, f"SMS to {peer}: delivered")
        else:
            why = rec.get("error") or "no reason reported"
            await self.edit(chat, message_id, f"SMS to {peer}: FAILED — {why}")

    # ---------------- lines ----------------

    def _resolve_line(self, chat: str, arg: str) -> tuple[str | None, str]:
        """(line id, error). Explicit argument wins, then the chat's /use pick, then the only
        configured line — a single-SIM gateway should never need /use."""
        ids = [str(i.get("id")) for i in cfg.list_instances()]
        if not ids:
            return None, "No lines are configured yet."
        if arg:
            wanted = arg.split()[0]
            return (wanted, "") if wanted in ids else (None, f"No line {wanted}. Have: {', '.join(ids)}")
        current = self._chat_line.get(chat)
        if current and current in ids:
            return current, ""
        if len(ids) == 1:
            return ids[0], ""
        return None, f"Several lines configured ({', '.join(ids)}) — /use <line> or pass one."

    # ---------------- commands ----------------

    async def _cmd_status(self, chat: str, _arg: str, _msg: dict):
        data = await _routes().api_instances()
        lines = []
        for inst in data.get("instances", []):
            st = inst.get("status") or {}
            name = inst.get("name") or f"Line {inst.get('id')}"
            row = f"{inst.get('id')}. {name}: {st.get('label') or st.get('state') or 'unknown'}"
            number = (st.get("detail") or {}).get("msisdn") or inst.get("msisdn")
            if number:
                row += f" ({number})"
            if st.get("reason") and st.get("state") not in ("OK", "STOPPED"):
                row += f"\n   {st['reason']}"
            lines.append(row)
        await self.send(chat, "\n".join(lines) or "No lines are configured yet.")

    async def _cmd_lines(self, chat: str, _arg: str, _msg: dict):
        current = self._chat_line.get(chat)
        rows = []
        for inst in cfg.list_instances():
            iid = str(inst.get("id"))
            mark = " <- current" if iid == current else ""
            # The number the SIM answers as is the one thing that tells two
            # lines apart at a glance; it is read from the SIM, so it can be blank.
            number = str(inst.get("msisdn") or "").strip() or "number unknown"
            rows.append(f"{iid}. {number} · {inst.get('name') or 'unnamed'} "
                        f"{inst.get('mcc')}-{inst.get('mnc')}{mark}")
        await self.send(chat, "\n".join(rows) or "No lines are configured yet.")

    async def _cmd_use(self, chat: str, arg: str, _msg: dict):
        iid, err = self._resolve_line(chat, arg)
        if not iid:
            await self.send(chat, err or "Usage: /use <line>")
            return
        self._chat_line[chat] = iid
        await self.send(chat, f"Commands in this chat now act on line {iid}.")

    async def _cmd_sms(self, chat: str, arg: str, _msg: dict):
        number, _, text = arg.partition(" ")
        if not number or not text.strip():
            await self.send(chat, "Usage: /sms <number> <text>")
            return
        iid, err = self._resolve_line(chat, "")
        if not iid:
            await self.send(chat, err)
            return
        await self._send_sms(chat, iid, number.strip(), text.strip())

    async def _send_sms(self, chat: str, iid: str, peer: str, text: str):
        try:
            res = await _routes().api_sms_send(iid, {"to": peer, "body": text})
        except HTTPException as e:
            await self.send(chat, f"Could not send: {_explain(e)}")
            return
        rec = res.get("message") or {}
        if res.get("ok") is False:
            await self.send(chat, f"SMS to {peer}: rejected — {res.get('error') or 'unknown'}")
            return
        mid = await self.send(chat, f"SMS to {peer}: sent, awaiting delivery")
        self._track_send(rec.get("id"), chat, mid)

    async def _cmd_msgs(self, chat: str, arg: str, _msg: dict):
        """No argument lists the recent conversations; a number opens one of them."""
        iid, err = self._resolve_line(chat, "")
        if not iid:
            await self.send(chat, err)
            return
        peer = arg.split()[0] if arg.strip() else ""
        if peer:
            rows = store.list_messages(iid, peer, limit=200)[-15:]
            if not rows:
                await self.send(chat, f"No messages with {peer} on line {iid}.")
                return
            out = [f"Line {iid} <-> {peer}"]
            for m in rows:
                when = time.strftime("%m-%d %H:%M", time.localtime(m.get("ts", 0)))
                arrow = "->" if m.get("direction") == "out" else "<-"
                out.append(f"{when} {arrow} {m.get('body')}")
            await self.send(chat, "\n".join(out))
            return
        threads = store.list_threads(iid)[:10]
        if not threads:
            await self.send(chat, "No messages on this line yet.")
            return
        out = [f"Line {iid} — recent conversations (/msgs <number> to open one)"]
        for t in threads:
            when = time.strftime("%m-%d %H:%M", time.localtime(t.get("last_ts", 0)))
            out.append(f"{when} {t.get('peer')} ({t.get('n')}): {t.get('last_body')}")
        await self.send(chat, "\n".join(out))

    async def _line_action(self, chat: str, arg: str, verb: str, run):
        iid, err = self._resolve_line(chat, arg)
        if not iid:
            await self.send(chat, err)
            return
        try:
            await run(iid)
        except HTTPException as e:
            await self.send(chat, f"Line {iid}: {verb} refused — {_explain(e)}")
            return
        except Exception as e:  # noqa
            await self.send(chat, f"Line {iid}: {verb} failed — {e}")
            return
        await self.send(chat, f"Line {iid}: {verb} done.")

    async def _cmd_line_start(self, chat: str, arg: str, _msg: dict):
        await self._line_action(chat, arg, "start",
                                lambda iid: _routes().api_instance_start(iid, None))

    async def _cmd_line_register(self, chat: str, arg: str, _msg: dict):
        await self._line_action(chat, arg, "re-register",
                                lambda iid: _routes().api_instance_register(iid))

    async def _cmd_line_stop(self, chat: str, arg: str, _msg: dict):
        await self._confirm(chat, arg, "stop", "Stopping drops calls and IMS registration.",
                            lambda iid: _routes().api_instance_stop(iid))

    async def _cmd_line_reprovision(self, chat: str, arg: str, _msg: dict):
        await self._confirm(chat, arg, "re-provision",
                            "Re-provisioning restarts the engine and interrupts calls.",
                            lambda iid: _routes().api_reprovision(iid, None))

    async def _cmd_pin(self, chat: str, arg: str, msg: dict):
        # The PIN would otherwise sit in the chat history forever, and Telegram keeps it server
        # side too. Remove the user's message before doing anything slow with it.
        await self.delete(chat, msg.get("message_id"))
        parts = arg.split()
        if not parts:
            await self.send(chat, "Usage: /pin <line> <pin>")
            return
        pin = parts[-1]
        iid, err = self._resolve_line(chat, " ".join(parts[:-1]))
        if not iid:
            await self.send(chat, err)
            return
        try:
            await _routes().api_instance_start(iid, {"pin": pin})
        except HTTPException as e:
            await self.send(chat, f"Line {iid}: {_explain(e)}")
            return
        await self.send(chat, f"Line {iid}: PIN accepted, starting.")

    # ---------------- confirmations ----------------

    async def _ask(self, chat: str, prompt: str, run, yes: str = "Confirm",
                   cancelled: str = "Cancelled."):
        """Put an action behind a yes/no prompt. `run` receives a resolve(text) callback that
        rewrites the prompt, so every outcome lands in the message that asked the question."""
        self._expire_pending()
        # A counter, not a timestamp: two confirmations raised in the same millisecond would
        # otherwise share a token, and the first button would act on the second one's target.
        self._confirm_seq += 1
        token = str(self._confirm_seq)
        self._pending[token] = {"chat": chat, "run": run, "cancelled": cancelled,
                                "ts": time.time()}
        await self.send(chat, prompt,
                        keyboard=[[{"text": yes, "callback_data": f"go:{token}"},
                                   {"text": "Cancel", "callback_data": f"no:{token}"}]])

    async def _confirm(self, chat: str, arg: str, verb: str, warning: str, run):
        iid, err = self._resolve_line(chat, arg)
        if not iid:
            await self.send(chat, err)
            return

        async def _do(resolve):
            await resolve(f"Line {iid}: {verb} in progress…")
            try:
                await run(iid)
            except HTTPException as e:
                await resolve(f"Line {iid}: {verb} refused — {_explain(e)}")
                return
            except Exception as e:  # noqa
                await resolve(f"Line {iid}: {verb} failed — {e}")
                return
            await resolve(f"Line {iid}: {verb} done.")

        await self._ask(chat, f"{warning}\nConfirm {verb} of line {iid}?", _do,
                        yes=f"Yes, {verb}", cancelled=f"Cancelled — line {iid} left alone.")

    def _expire_pending(self):
        cutoff = time.time() - _CONFIRM_TTL
        for token in [k for k, v in self._pending.items() if v["ts"] < cutoff]:
            self._pending.pop(token, None)

    async def _handle_callback(self, cb: dict, commands: dict):
        """The outcome rewrites the question rather than answering below it. editMessageText
        without reply_markup also drops the buttons, which is what stops a second tap from
        running the action again while the first one is still going."""
        data = cb.get("data") or ""
        prompt = cb.get("message") or {}
        chat = str((prompt.get("chat") or {}).get("id") or "")
        message_id = prompt.get("message_id")

        async def resolve(text: str):
            if message_id:
                await self.edit(chat, message_id, text)
            else:
                await self.send(chat, text)

        await self._api("answerCallbackQuery", {"callback_query_id": cb.get("id")}, timeout=10)
        self._expire_pending()
        action, _, token = data.partition(":")
        # Reader / eUICC picks are plain selections, not guarded actions. Re-check the
        # switch: an old button in the chat must not keep working after eSIM is turned off.
        if action in ("esr", "ese") and not commands.get("allow_esim"):
            await resolve("eSIM management is disabled for this bot "
                          "(Settings -> Telegram -> allow eSIM).")
            return
        if action == "esr":
            await self._select_reader(chat, int(token), self._reader_name(int(token)),
                                      resolve=resolve)
            return
        if action == "ese":
            await self._select_se(chat, token, resolve)
            return
        pending = self._pending.pop(token, None)
        if not pending or pending["chat"] != chat:
            await resolve("That confirmation has expired — run the command again.")
            return
        if action != "go":
            await resolve(pending.get("cancelled") or "Cancelled.")
            return
        try:
            await pending["run"](resolve)
        except Exception as e:  # noqa
            log.exception("telegram: confirmed action failed: %r", e)
            await resolve(f"Failed — {e}")

    # ---------------- eSIM ----------------

    def _reader_name(self, index: int) -> str:
        for c in _routes().hub.cards_list():
            if c.get("index") == index:
                return c.get("name") or ""
        return ""

    async def _esim_ready(self, chat: str) -> bool:
        """lpac is an optional local build; without it every LPA call 503s. Say so once."""
        st = await _routes().api_esim_status()
        if st.get("available"):
            return True
        await self.send(chat, "eSIM needs the local lpac build, which isn't installed.\n"
                              "On the gateway: sudo ./install.sh build-lpac")
        return False

    def _target(self, chat: str) -> dict | None:
        t = self._esim_target.get(chat)
        if t and time.time() - t["ts"] < _ESIM_TARGET_TTL:
            return t
        self._esim_target.pop(chat, None)
        return None

    def _target_args(self, chat: str) -> dict:
        t = self._target(chat) or {}
        args = {"reader": t.get("reader"), "reader_index": t.get("index", 0)}
        if t.get("se_id"):
            args["se_id"] = t["se_id"]
        return args

    async def _esim_call(self, chat: str, describe: str, factory, resolve=None):
        """Run one LPA operation and turn its two actionable failures into something the chat
        can resolve: lpac missing, and a line holding the reader (which needs a stop first)."""
        say = resolve or (lambda text: self.send(chat, text))
        try:
            return await factory(), True
        except HTTPException as e:
            detail = e.detail if isinstance(e.detail, str) else str(e.detail)
            if e.status_code == 503:
                await say("eSIM needs the local lpac build: sudo ./install.sh build-lpac")
            elif e.status_code == 409 and "running on this reader" in detail:
                await self._offer_stop_and_retry(chat, detail, describe, factory)
            elif e.status_code == 409:
                await say(f"{describe} not possible right now — {detail}")
            elif e.status_code == 400 and "SE" in detail:
                await say("This card has two eUICCs — run /esim first and pick one.")
            else:
                await say(f"{describe} failed — {_explain(e)}")
        except Exception as e:  # noqa
            await say(f"{describe} failed — {e}")
        return None, False

    async def _offer_stop_and_retry(self, chat: str, detail: str, describe: str, factory):
        """lpac needs the card exclusively, so the most common eSIM failure is 'a line is using
        this reader'. Handing that 409 to the user as-is would make them go and stop it by hand,
        so offer the whole sequence — stop, retry, offer to start again — behind one button."""
        m = re.search(r"Line (\S+) is running", detail)
        iid = m.group(1) if m else None
        if not iid:
            await self.send(chat, detail)
            return

        async def _do(resolve):
            await resolve(f"Stopping line {iid}…")
            try:
                await _routes().api_instance_stop(iid)
            except Exception as e:  # noqa
                await resolve(f"Could not stop line {iid}: {e}")
                return
            await resolve(f"Line {iid} stopped. {describe}…")
            _, ok = await self._esim_call(chat, describe, factory, resolve=resolve)
            if ok:
                await resolve(f"Line {iid} stopped, {describe} done.")
            await self._ask(
                chat, f"Start line {iid} again?",
                lambda r: self._restart_line(r, iid), yes=f"Start line {iid}",
                cancelled=f"Left line {iid} stopped.")

        await self._ask(
            chat,
            f"Line {iid} is using this reader and lpac needs it exclusively.\n"
            f"Stop line {iid} and {describe}?",
            _do, yes=f"Stop line {iid} and continue",
            cancelled=f"Cancelled — line {iid} left running.")

    async def _restart_line(self, resolve, iid: str):
        await resolve(f"Starting line {iid}…")
        try:
            await _routes().api_instance_start(iid, None)
        except HTTPException as e:
            await resolve(f"Line {iid} did not start — {_explain(e)}")
            return
        await resolve(f"Line {iid} started.")

    async def _cmd_esim(self, chat: str, arg: str, _msg: dict):
        """Pick the reader (and, on a dual-SE card, the eUICC) these commands act on."""
        if not await self._esim_ready(chat):
            return
        cards = (await _routes().api_cards()).get("cards") or []
        present = [c for c in cards if c.get("present")]
        if not present:
            await self.send(chat, "No card is present in any reader.")
            return
        if len(present) > 1 and not arg.strip():
            await self.send(chat, "Which reader?", keyboard=[
                [{"text": f"{c.get('index')}: {c.get('name')}",
                  "callback_data": f"esr:{c.get('index')}"}] for c in present[:8]])
            return
        pick = present[0]
        if arg.strip():
            wanted = arg.split()[0]
            pick = next((c for c in present if str(c.get("index")) == wanted), None)
            if not pick:
                have = ", ".join(str(c.get("index")) for c in present)
                await self.send(chat, f"No reader {wanted}. Have: {have}")
                return
        await self._select_reader(chat, pick.get("index"), pick.get("name"))

    async def _select_reader(self, chat: str, index, name: str, resolve=None):
        self._esim_target[chat] = {"reader": name, "index": index, "se_id": None,
                                   "aid": None, "ts": time.time()}
        say = resolve or (lambda text: self.send(chat, text))
        payload, ok = await self._esim_call(
            chat, "reading the chip",
            lambda: _routes().api_esim_chip(reader_index=index, reader=name), resolve=resolve)
        if not ok:
            return
        ses = payload.get("ses") or []
        if payload.get("dual") and len(ses) > 1:
            await self.send(chat, f"Reader {index} has two eUICCs — which one?", keyboard=[
                [{"text": f"{se.get('label') or se.get('id')} · {se.get('eid') or 'no EID'}",
                  "callback_data": f"ese:{se.get('id')}"}] for se in ses])
            return
        if ses:
            self._esim_target[chat].update(se_id=ses[0].get("id"), aid=ses[0].get("aid"))
        await say(_format_chip(index, name, payload))

    async def _select_se(self, chat: str, se_id: str, resolve):
        t = self._target(chat)
        if not t:
            await resolve("That selection expired — run /esim again.")
            return
        t.update(se_id=se_id, ts=time.time())
        payload, ok = await self._esim_call(
            chat, "reading the chip",
            lambda: _routes().api_esim_chip(reader_index=t["index"], reader=t["reader"]),
            resolve=resolve)
        if not ok:
            return
        se = next((s for s in (payload.get("ses") or []) if s.get("id") == se_id), None)
        if se:
            t["aid"] = se.get("aid")
        await resolve(_format_chip(t["index"], t["reader"], payload, only=se_id))

    async def _need_target(self, chat: str) -> dict | None:
        if not await self._esim_ready(chat):
            return None
        t = self._target(chat)
        if not t:
            await self.send(chat, "Pick a reader first with /esim.")
            return None
        return t

    async def _cmd_esim_profiles(self, chat: str, _arg: str, _msg: dict):
        t = await self._need_target(chat)
        if not t:
            return
        payload, ok = await self._esim_call(
            chat, "listing profiles",
            lambda: _routes().api_esim_profiles(reader_index=t["index"], reader=t["reader"]))
        if not ok:
            return
        await self.send(chat, _format_profiles(payload, t.get("se_id")))

    async def _cmd_esim_notify(self, chat: str, _arg: str, _msg: dict):
        t = await self._need_target(chat)
        if not t:
            return
        payload, ok = await self._esim_call(
            chat, "listing notifications",
            lambda: _routes().api_esim_notifications(reader_index=t["index"],
                                                     reader=t["reader"]))
        if not ok:
            return
        rows = payload.get("notifications") or []
        if not rows:
            await self.send(chat, "No pending notifications.")
            return
        out = ["Pending notifications (/esim_notify_process <seq|all>)"]
        for n in rows[:20]:
            seq = n.get("seqNumber", n.get("seq"))
            op = n.get("profileManagementOperation") or n.get("operation") or "notify"
            out.append(f"#{seq} {op} {n.get('iccid') or '—'} "
                       f"{n.get('notificationAddress') or n.get('address') or ''}".rstrip())
        await self.send(chat, "\n".join(out))

    async def _cmd_esim_notify_process(self, chat: str, arg: str, _msg: dict):
        t = await self._need_target(chat)
        if not t:
            return
        which = arg.split()[0] if arg.strip() else "all"
        body = dict(self._target_args(chat), remove=True)
        if which != "all":
            try:
                body["seq"] = int(which)
            except ValueError:
                await self.send(chat, "Usage: /esim_notify_process <seq|all>")
                return
        _, ok = await self._esim_call(
            chat, "processing notifications",
            lambda: _routes().api_esim_notifications_process(body))
        if ok:
            await self.send(chat, f"Processed {'all notifications' if which == 'all' else '#' + which}.")

    async def _profile_op(self, chat: str, arg: str, verb: str, factory_for):
        t = await self._need_target(chat)
        if not t:
            return
        iccid = arg.split()[0] if arg.strip() else ""
        if not iccid:
            await self.send(chat, f"Usage: /esim_{verb} <iccid>  (/esim_profiles lists them)")
            return

        async def _do(resolve):
            await resolve(f"{verb.capitalize()} {iccid}…")
            _, ok = await self._esim_call(chat, f"{verb} of {iccid}",
                                          factory_for(iccid), resolve=resolve)
            if not ok:
                return
            await resolve(f"Profile {iccid} {verb}d.\n"
                          "Switching profiles changes the card's ICCID, so a line bound to the "
                          "old one will now refuse to start — provision the active profile as "
                          "its own line. /status shows where each line stands.")

        await self._ask(chat, f"{verb.capitalize()} profile {iccid} on reader {t['index']}?",
                        _do, yes=f"Yes, {verb}", cancelled=f"Cancelled — {iccid} untouched.")

    async def _cmd_esim_enable(self, chat: str, arg: str, _msg: dict):
        await self._profile_op(chat, arg, "enable", lambda iccid: (
            lambda: _routes().api_esim_enable(iccid, self._target_args(chat))))

    async def _cmd_esim_disable(self, chat: str, arg: str, _msg: dict):
        await self._profile_op(chat, arg, "disable", lambda iccid: (
            lambda: _routes().api_esim_disable(iccid, self._target_args(chat))))

    async def _cmd_esim_delete(self, chat: str, arg: str, _msg: dict):
        """Deleting a profile is the one irreversible thing this bot can do — a downloaded
        profile usually cannot be fetched again. A button is too easy to hit by accident, so
        this one asks the operator to type part of the ICCID back."""
        t = await self._need_target(chat)
        if not t:
            return
        iccid = arg.split()[0] if arg.strip() else ""
        if len(iccid) < 4:
            await self.send(chat, "Usage: /esim_delete <iccid>  (/esim_profiles lists them)")
            return
        args = self._target_args(chat)

        async def _run():
            return await _routes().api_esim_delete(
                iccid, reader_index=args.get("reader_index", 0), reader=args.get("reader"),
                se_id=args.get("se_id"))

        self._typed[chat] = {"expect": iccid[-4:], "iccid": iccid, "run": _run,
                             "ts": time.time()}
        await self.send(chat, f"This permanently deletes profile {iccid}. A deleted profile "
                              f"usually cannot be downloaded again.\n"
                              f"Type the last 4 digits ({'*' * (len(iccid) - 4)}____) to confirm, "
                              f"or /cancel.")

    async def _handle_typed_confirmation(self, chat: str, text: str) -> bool:
        pending = self._typed.get(chat)
        if not pending:
            return False
        if time.time() - pending["ts"] > _CONFIRM_TTL:
            self._typed.pop(chat, None)
            await self.send(chat, "That confirmation expired — run the command again.")
            return True
        if text.strip() == "/cancel":
            self._typed.pop(chat, None)
            await self.send(chat, "Cancelled — nothing was deleted.")
            return True
        if text.strip() != pending["expect"]:
            self._typed.pop(chat, None)
            await self.send(chat, "That doesn't match — nothing was deleted.")
            return True
        self._typed.pop(chat, None)
        _, ok = await self._esim_call(chat, f"deleting {pending['iccid']}", pending["run"])
        if ok:
            await self.send(chat, f"Profile {pending['iccid']} deleted.")
        return True

    async def _cmd_esim_download(self, chat: str, arg: str, msg: dict):
        # An activation code is single-use and worth stealing: whoever redeems it first gets
        # the profile. Take it out of the chat history before doing anything with it — but
        # only after we know we have a reader, otherwise the code is gone and the user has
        # to paste it again.
        code = arg.strip()
        if not code:
            await self.send(chat, "Usage: /esim_download LPA:1$smdp.example.com$MATCHINGID")
            return
        t = await self._need_target(chat)
        if not t:
            return
        await self.delete(chat, msg.get("message_id"))
        body = dict(self._target_args(chat), activation_code=code)
        res, ok = await self._esim_call(
            chat, "starting the download", lambda: _routes().api_esim_download(body))
        if not ok:
            return
        mid = await self.send(chat, f"Download starting on reader {t['index']}…")
        if mid:
            self._downloads[res.get("reader") or t["reader"]] = {
                "chat": chat, "message_id": mid, "last_edit": 0.0, "lines": []}

    async def _on_download_event(self, msg: dict):
        """One message per download, edited in place: a profile install emits dozens of steps
        and posting each would bury the chat."""
        track = self._downloads.get(msg.get("reader"))
        if not track:
            return
        event, step = msg.get("event"), msg.get("step") or ""
        if event == "preview":
            meta = msg.get("metadata") or {}
            name = meta.get("profileName") or meta.get("serviceProviderName") or "profile"
            track["lines"].append(f"Found: {name} {meta.get('iccid') or ''}".rstrip())
        elif event == "completed":
            track["lines"].append("Installed.")
        elif event == "error":
            track["lines"].append(f"FAILED — {msg.get('error') or step or 'unknown'}")
        elif event == "cancelling":
            track["lines"].append("Cancelling…")
        elif step:
            track["lines"].append(step)
        head = f"eSIM download on reader {msg.get('reader_index', '?')}"
        body = "\n".join([head] + track["lines"][-8:])
        terminal = event in ("completed", "error")
        # Telegram rate-limits edits, and progress can arrive several times a second.
        if not terminal and time.monotonic() - track["last_edit"] < 2.0:
            return
        track["last_edit"] = time.monotonic()
        await self.edit(track["chat"], track["message_id"], body)
        if terminal:
            self._downloads.pop(msg.get("reader"), None)
            if event == "completed":
                await self.send(track["chat"],
                                "The card's ICCID changed with the new profile, so any line "
                                "bound to the old one will refuse to start until you provision "
                                "the active profile as its own line.")

    # ---------------- dispatch ----------------

    _SMS_COMMANDS = {
        "/start": None, "/help": None,
        "/status": "_cmd_status", "/lines": "_cmd_lines", "/use": "_cmd_use",
        "/sms": "_cmd_sms", "/msgs": "_cmd_msgs",
    }
    _MANAGEMENT_COMMANDS = {
        "/line_start": "_cmd_line_start", "/line_stop": "_cmd_line_stop",
        "/line_register": "_cmd_line_register", "/line_reprovision": "_cmd_line_reprovision",
        "/pin": "_cmd_pin",
    }
    _ESIM_COMMANDS = {
        "/esim": "_cmd_esim", "/esim_profiles": "_cmd_esim_profiles",
        "/esim_enable": "_cmd_esim_enable", "/esim_disable": "_cmd_esim_disable",
        "/esim_delete": "_cmd_esim_delete", "/esim_download": "_cmd_esim_download",
        "/esim_notify": "_cmd_esim_notify",
        "/esim_notify_process": "_cmd_esim_notify_process",
    }

    async def _handle_message(self, msg: dict, commands: dict):
        chat = str(((msg.get("chat") or {}).get("id")) or "")
        text = (msg.get("text") or "").strip()
        if not text:
            return

        # A type-this-back confirmation owns the next message from this chat, whatever it is.
        if self._typed.get(chat):
            if not commands.get("allow_esim"):
                self._typed.pop(chat, None)
                await self.send(chat, "eSIM management is disabled for this bot "
                                      "(Settings -> Telegram -> allow eSIM).")
                return
            if await self._handle_typed_confirmation(chat, text):
                return

        # A plain reply to an incoming-SMS notification answers that conversation.
        reply_to = (msg.get("reply_to_message") or {}).get("message_id")
        if not text.startswith("/") and reply_to in self._reply_targets:
            iid, peer = self._reply_targets[reply_to]
            await self._send_sms(chat, iid, peer, text)
            return

        cmd, arg = _cmd_and_args(text)
        if cmd in ("/start", "/help"):
            await self.send(chat, _HELP)
            return
        handler = self._SMS_COMMANDS.get(cmd)
        if handler is None and cmd in self._MANAGEMENT_COMMANDS:
            if not commands.get("allow_management"):
                await self.send(chat, "Line control is disabled for this bot "
                                      "(Settings -> Telegram -> allow line control).")
                return
            handler = self._MANAGEMENT_COMMANDS[cmd]
        if handler is None and cmd in self._ESIM_COMMANDS:
            if not commands.get("allow_esim"):
                await self.send(chat, "eSIM management is disabled for this bot "
                                      "(Settings -> Telegram -> allow eSIM).")
                return
            handler = self._ESIM_COMMANDS[cmd]
        if not handler:
            if cmd in _USERBOT_COMMANDS:
                await self._point_at_userbot(chat, cmd)
            elif text.startswith("/"):
                await self.send(chat, "Unknown command. /help lists what I understand.")
            return
        await getattr(self, handler)(chat, arg, msg)

    async def _point_at_userbot(self, chat: str, cmd: str):
        """Calls are bridged by a different Telegram account, so this command is
        not unknown - it is just in the wrong chat. Say which chat, and whether
        the thing is even running."""
        try:
            phone = str(userbot_cfg.load().get("phone") or "").strip()
            live = bool(userbot_cfg.status().get("running"))
        except Exception as e:  # noqa
            log.debug("userbot lookup for %s: %s", cmd, e)
            phone, live = "", False
        if not phone:
            await self.send(chat, f"{cmd} belongs to the call bridge, which is not set up yet. "
                                  "Settings -> Telegram calls (userbot).")
            return
        tail = "" if live else " It is not running right now — start it in Settings."
        await self.send(chat, f"{cmd} belongs to the userbot account ({phone}), not to me. "
                              f"Send it in that account's own chat.{tail}")

    async def _handle_update(self, update: dict, tg: dict, commands: dict):
        msg = update.get("message") or update.get("edited_message")
        cb = update.get("callback_query")
        chat_id = None
        if msg:
            chat_id = ((msg.get("chat") or {}).get("id"))
        elif cb:
            chat_id = (((cb.get("message") or {}).get("chat") or {}).get("id"))
        if chat_id is None:
            return
        if not _chat_allowed(tg, chat_id):
            # Silent: answering would confirm to a stranger that this bot controls something.
            log.warning("telegram: ignoring command from unauthorised chat %s", chat_id)
            return
        if cb:
            await self._handle_callback(cb, commands)
            return
        sent_at = msg.get("date") or 0
        if sent_at and time.time() - sent_at > _STALE_UPDATE_AGE:
            log.info("telegram: dropping stale command (%.0fs old)", time.time() - sent_at)
            return
        await self._handle_message(msg, commands)

    # ---------------- poll loop ----------------

    async def _drain_backlog(self) -> bool:
        """Align the offset with the newest pending update without acting on any of them.
        offset=-1 asks for just the last one; confirming it discards everything before it.
        Returns False if the call failed — the caller must NOT poll without an offset, or
        the unconfirmed backlog (up to 24h of commands) would execute."""
        ok, res = await self._api("getUpdates", {"offset": -1, "timeout": 0}, timeout=20)
        if not ok:
            log.warning("telegram: could not drain backlog (%s)", (res or {}).get("error"))
            return False
        if res:
            self._offset = res[-1]["update_id"] + 1
            log.info("telegram: skipped %d queued update(s) from before this start", len(res))
        else:
            self._offset = 0
        return True

    async def run(self):
        """Poll for commands whenever the feature is switched on. Settings are re-read every
        cycle so enabling, disabling or re-tokening the bot takes effect without a restart."""
        self._unsubscribe = self.hub.subscribe(self.on_event)
        try:
            while True:
                tg = (cfg.get_settings().get("telegram") or {})
                commands = tg.get("commands") or {}
                token = (tg.get("bot_token") or "").strip()
                if not (tg.get("enabled") and commands.get("enabled") and token):
                    self._token, self._offset = "", None
                    await asyncio.sleep(_IDLE_SLEEP)
                    continue
                if token != self._token:
                    self._token, self._offset = token, None
                    log.info("telegram: command polling active")
                if self._offset is None:
                    if not await self._drain_backlog():
                        await asyncio.sleep(_ERROR_SLEEP)
                        continue
                await self._poll_once(tg, commands)
        except asyncio.CancelledError:
            raise
        finally:
            if self._unsubscribe:
                self._unsubscribe()

    async def _poll_once(self, tg: dict, commands: dict):
        payload = {"timeout": POLL_TIMEOUT, "allowed_updates": ["message", "callback_query"]}
        if self._offset is not None:
            payload["offset"] = self._offset
        ok, res = await self._api("getUpdates", payload)
        if not ok:
            status, err = res.get("status"), res.get("error")
            if status == 409:
                # Another poller or a registered webhook owns this token. Retrying fast just
                # trades 409s with it, so back off loudly instead.
                log.warning("telegram: getUpdates conflict (another poller or a webhook is "
                            "using this token) — retrying in %ss", _CONFLICT_SLEEP)
                await asyncio.sleep(_CONFLICT_SLEEP)
                return
            if status == 401:
                log.warning("telegram: bot token rejected — command polling paused")
                self._token = ""
                await asyncio.sleep(_CONFLICT_SLEEP)
                return
            wait = res.get("retry_after") or _ERROR_SLEEP
            log.warning("telegram: getUpdates failed (%s) — retrying in %ss", err, wait)
            await asyncio.sleep(float(wait))
            return
        for update in res or []:
            self._offset = update["update_id"] + 1
            try:
                await self._handle_update(update, tg, commands)
            except Exception as e:  # noqa
                log.exception("telegram: update handling failed: %r", e)


def _bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "?"
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"


def _profile_label(p: dict) -> str:
    """Nickname first, then the operator's own name — matching what the WebUI shows."""
    return ((p.get("profileNickname") or "").strip()
            or (p.get("profileName") or "").strip()
            or (p.get("serviceProviderName") or "").strip()
            or "Profile")


def _format_chip(index, name: str, payload: dict, only: str | None = None) -> str:
    ses = [se for se in (payload.get("ses") or []) if not only or se.get("id") == only]
    out = [f"Reader {index}: {name}"]
    if payload.get("line_running"):
        out.append(f"Line {payload.get('matched_instance')} is running on it — eSIM changes "
                   f"need it stopped first (I'll offer to do that).")
    for se in ses:
        out.append(f"{se.get('label') or se.get('id')} · EID {se.get('eid') or '—'} · "
                   f"{_bytes(se.get('freeSpace'))} free · "
                   f"{len(se.get('profiles') or [])} profile(s)")
    out.append("/esim_profiles to list them")
    return "\n".join(out)


def _format_profiles(payload: dict, only: str | None = None) -> str:
    ses = [se for se in (payload.get("ses") or []) if not only or se.get("id") == only]
    out = []
    for se in ses:
        profiles = se.get("profiles") or []
        if len(ses) > 1:
            out.append(f"— {se.get('label') or se.get('id')} —")
        if not profiles:
            out.append("(no profiles)")
        for p in profiles:
            enabled = str(p.get("profileState") or "").lower() == "enabled"
            out.append(f"{'[on] ' if enabled else '[off] '}{_profile_label(p)}\n"
                       f"      {p.get('iccid')}")
    if not out:
        return "No profiles on this card."
    out.append("/esim_enable <iccid> · /esim_disable <iccid> · /esim_delete <iccid>")
    return "\n".join(out)


def _chat_allowed(tg: dict, chat_id) -> bool:
    """Commands are accepted only from explicitly listed chats. An empty allow-list falls back
    to the chat notifications already go to; with neither configured, nothing is accepted."""
    commands = tg.get("commands") or {}
    allowed = [str(c).strip() for c in (commands.get("allowed_chats") or []) if str(c).strip()]
    if not allowed:
        fallback = str(tg.get("chat_id") or "").strip()
        allowed = [fallback] if fallback else []
    return str(chat_id) in allowed
