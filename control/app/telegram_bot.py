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
import time
from collections import OrderedDict

import requests
from fastapi import HTTPException

from . import config as cfg
from . import store

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
/pin <line> <pin> - unlock and start"""

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
        verdict arrives later from the delivery watcher, so rewrite the original chat line."""
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
            rows.append(f"{iid}. {inst.get('name') or 'unnamed'} "
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

    async def _confirm(self, chat: str, arg: str, verb: str, warning: str, run):
        iid, err = self._resolve_line(chat, arg)
        if not iid:
            await self.send(chat, err)
            return
        self._expire_pending()
        # A counter, not a timestamp: two confirmations raised in the same millisecond would
        # otherwise share a token, and the first button would act on the second line.
        self._confirm_seq += 1
        token = str(self._confirm_seq)
        self._pending[token] = {"chat": chat, "iid": iid, "verb": verb, "run": run,
                                "ts": time.time()}
        await self.send(chat, f"{warning}\nConfirm {verb} of line {iid}?",
                        keyboard=[[{"text": f"Yes, {verb}", "callback_data": f"go:{token}"},
                                   {"text": "Cancel", "callback_data": f"no:{token}"}]])

    def _expire_pending(self):
        cutoff = time.time() - _CONFIRM_TTL
        for token in [k for k, v in self._pending.items() if v["ts"] < cutoff]:
            self._pending.pop(token, None)

    async def _handle_callback(self, cb: dict):
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
        pending = self._pending.pop(token, None)
        if not pending or pending["chat"] != chat:
            await resolve("That confirmation has expired — run the command again.")
            return
        if action != "go":
            await resolve(f"Cancelled — line {pending['iid']} left alone.")
            return
        iid, verb = pending["iid"], pending["verb"]
        await resolve(f"Line {iid}: {verb} in progress…")
        try:
            await pending["run"](iid)
        except HTTPException as e:
            await resolve(f"Line {iid}: {verb} refused — {_explain(e)}")
            return
        except Exception as e:  # noqa
            await resolve(f"Line {iid}: {verb} failed — {e}")
            return
        await resolve(f"Line {iid}: {verb} done.")

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

    async def _handle_message(self, msg: dict, commands: dict):
        chat = str(((msg.get("chat") or {}).get("id")) or "")
        text = (msg.get("text") or "").strip()
        if not text:
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
        if not handler:
            if text.startswith("/"):
                await self.send(chat, "Unknown command. /help lists what I understand.")
            return
        await getattr(self, handler)(chat, arg, msg)

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
            await self._handle_callback(cb)
            return
        sent_at = msg.get("date") or 0
        if sent_at and time.time() - sent_at > _STALE_UPDATE_AGE:
            log.info("telegram: dropping stale command (%.0fs old)", time.time() - sent_at)
            return
        await self._handle_message(msg, commands)

    # ---------------- poll loop ----------------

    async def _drain_backlog(self):
        """Align the offset with the newest pending update without acting on any of them.
        offset=-1 asks for just the last one; confirming it discards everything before it."""
        ok, res = await self._api("getUpdates", {"offset": -1, "timeout": 0}, timeout=20)
        if ok and res:
            self._offset = res[-1]["update_id"] + 1
            log.info("telegram: skipped %d queued update(s) from before this start", len(res))
        elif ok:
            self._offset = None

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
                    await self._drain_backlog()
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


def _chat_allowed(tg: dict, chat_id) -> bool:
    """Commands are accepted only from explicitly listed chats. An empty allow-list falls back
    to the chat notifications already go to; with neither configured, nothing is accepted."""
    commands = tg.get("commands") or {}
    allowed = [str(c).strip() for c in (commands.get("allowed_chats") or []) if str(c).strip()]
    if not allowed:
        fallback = str(tg.get("chat_id") or "").strip()
        allowed = [fallback] if fallback else []
    return str(chat_id) in allowed
