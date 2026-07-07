"""
notify_push.py - Outbound push notifications for incoming events (SMS / calls).

Two independent, separately-configurable channels, both driven from global settings:
  - webhook : HTTP POST a JSON body to a user-supplied URL.
  - telegram: send a formatted message to a chat/channel via a Telegram bot.

Both fire on the SAME internal events (incoming_sms, incoming_call) and carry the same
core fields (SIM ICCID, the line's own MSISDN, the event's source number, the event type,
and the SMS text when applicable). Delivery is best-effort and MUST NOT block or break the
engine-event path: callers dispatch fire-and-forget and every network call is wrapped so a
failing/slow endpoint only logs a warning.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger("vowifi.push")

# Webhook targets are often internal hosts with self-signed TLS; we POST with verify=False
# (see _post_webhook), so silence urllib3's per-request InsecureRequestWarning to keep logs clean.
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
except Exception:  # noqa
    pass

# Event identifiers shared by both channels and the settings UI checkboxes.
EV_INCOMING_SMS = "incoming_sms"
EV_INCOMING_CALL = "incoming_call"

_TIMEOUT = 8  # seconds; keep short so a dead endpoint never piles up threads


def _events_enabled(chan: dict) -> dict:
    ev = chan.get("events") or {}
    # default: both on if the key is absent (a freshly-enabled channel notifies everything)
    return {
        EV_INCOMING_SMS: ev.get(EV_INCOMING_SMS, True),
        EV_INCOMING_CALL: ev.get(EV_INCOMING_CALL, True),
    }


def build_payload(event: str, instance: dict, source: str, text: str | None) -> dict:
    """The canonical event body both channels are built from. `instance` is the stored
    line config (for ICCID + MSISDN); `source` is the event's originating number; `text`
    is the SMS body (None for calls)."""
    return {
        "event": event,                                   # incoming_sms | incoming_call
        "instance": str(instance.get("id", "")),
        "sim_name": instance.get("name", "") or "",
        "iccid": instance.get("iccid", "") or "",
        "msisdn": instance.get("msisdn", "") or "",       # the line's own number (may be "")
        "from": source or "",                             # the event's source number
        "text": text if event == EV_INCOMING_SMS else None,   # SMS body, else null
    }


def _post_webhook(cfg: dict, payload: dict):
    url = (cfg.get("url") or "").strip()
    if not url:
        log.warning("webhook enabled but no URL configured; skipping")
        return
    try:
        # verify=False: webhook targets are frequently internal hosts with self-signed TLS;
        # we're pushing low-sensitivity event metadata, not accepting input, so don't let a
        # cert mismatch silently drop notifications.
        r = requests.post(url, json=payload, timeout=_TIMEOUT, verify=False,
                          headers={"User-Agent": "vowifi-gateway"})
        log.info("webhook %s -> %s (%s)", payload.get("event"), url, r.status_code)
    except Exception as e:  # noqa
        log.warning("webhook POST to %s failed: %r", url, e)


def _telegram_text(payload: dict) -> str:
    ev = payload.get("event")
    head = "📩 Incoming SMS" if ev == EV_INCOMING_SMS else "📞 Incoming call"
    name = payload.get("sim_name") or payload.get("iccid") or payload.get("instance")
    msisdn = payload.get("msisdn")
    sim_line = f"SIM: {name}" + (f" ({msisdn})" if msisdn else "")
    lines = [head, sim_line, f"From: {payload.get('from') or 'unknown'}"]
    if ev == EV_INCOMING_SMS:
        lines.append("")
        lines.append(payload.get("text") or "")
    return "\n".join(lines)


def _post_telegram(cfg: dict, payload: dict):
    token = (cfg.get("bot_token") or "").strip()
    chat = str(cfg.get("chat_id") or "").strip()
    if not token or not chat:
        log.warning("telegram enabled but bot_token/chat_id missing; skipping")
        return
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat, "text": _telegram_text(payload),
                  "disable_web_page_preview": True},
            timeout=_TIMEOUT)
        if r.status_code != 200:
            log.warning("telegram sendMessage -> %s %s", r.status_code, r.text[:200])
        else:
            log.info("telegram %s -> chat %s ok", payload.get("event"), chat)
    except Exception as e:  # noqa
        log.warning("telegram sendMessage failed: %r", e)


def dispatch(settings: dict, event: str, instance: dict, source: str, text: str | None = None):
    """Fire both configured channels for one event. BLOCKING (does the HTTP itself) — the
    caller runs this off the event path (e.g. asyncio.to_thread + create_task) so a slow
    endpoint never stalls engine-event handling. Safe to call unconditionally: each channel
    is gated on its own enable flag + per-event checkbox."""
    try:
        payload = build_payload(event, instance, source, text)
        wh = settings.get("webhook") or {}
        if wh.get("enabled") and _events_enabled(wh).get(event):
            _post_webhook(wh, payload)
        tg = settings.get("telegram") or {}
        if tg.get("enabled") and _events_enabled(tg).get(event):
            _post_telegram(tg, payload)
    except Exception as e:  # noqa
        log.warning("push dispatch error: %r", e)
