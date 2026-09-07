"""
bridge.py - wires the Telegram leg to one of several SIP legs and orchestrates a call.

Every leg is a plain 48 kHz mono int16 pipe by the time it gets here, so the
bridge itself is only routing, ordering and teardown.

Routing: one SIP leg per SIM, one Telegram leg shared by every authorised
account, and at most one call at a time. `_active` is the leg the Telegram call
is currently joined to; audio only flows to and from that one, and a leg that is
merely ringing must never be mistaken for it.

Outbound (/call 12345):
  ring the account that asked on Telegram first, and only send the SIP INVITE
  once they have answered. Doing it the other way round would make the callee's
  phone ring while the caller is still reaching for theirs, and the first thing
  the callee hears would be silence.

Inbound (someone dials a SIM):
  the dialplan rings every local extension at once, us included. We reply 180
  Ringing and call that card's answerer on Telegram; only when they answer do we
  send 200 OK on the SIP leg. Answering first would cancel the other extensions
  - the browser softphone and any desk phone would stop ringing the moment the
  userbot picked up, which is not what "ring my phones" means.

Teardown is the subtle half. A Telegram call that never joined a SIP leg must
leave a ringing inbound call alone: declining on Telegram used to hang the
caller up after a single ring and silence every other extension with it.

Whatever the outcome, whoever was on the call gets a summary afterwards. For a
call nobody took that is the only trace the SIM rang at all.
"""
from __future__ import annotations

import asyncio
import logging
import time
from functools import partial

log = logging.getLogger("userbot.bridge")


def _span(seconds: float) -> str:
    total = max(0, int(seconds))
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m {total % 60:02d}s"
    return f"{total // 3600}h {total % 3600 // 60:02d}m"


def _caller_number(uri: str) -> str:
    """`"Someone" <sip:+85312345@ims.example>` -> `+85312345`."""
    text = str(uri or "")
    if "sip:" in text:
        text = text.split("sip:", 1)[1].split("@", 1)[0]
    return text.strip("<> ") or "unknown"


class CallBridge:
    def __init__(self, tg_leg, sip_legs: dict, cards: dict, loop: asyncio.AbstractEventLoop):
        self.tg = tg_leg
        self.legs = dict(sip_legs)          # line id -> SipLeg
        # line id -> {"answerer": Telegram user id to ring, "msisdn": the SIM's number}
        self.cards = dict(cards)
        self.loop = loop
        # The leg joined to the current Telegram call. None means no SIP call
        # belongs to us, even if some leg is ringing.
        self._active = None
        self._pending_outbound: tuple[str, str] | None = None   # (line, number)
        self._inbound: tuple[str, str] | None = None            # (line, caller)
        # What the current attempt is, so it can be reported once it is over.
        self._session: dict | None = None
        self._tearing_down = False

        self.tg.on_pcm = self._tg_to_sip
        self.tg.on_connected = self._tg_connected
        self.tg.on_ended = self._tg_ended
        for line, leg in self.legs.items():
            leg.on_pcm = partial(self._sip_to_tg, line)
            leg.on_incoming = partial(self._sip_incoming, line)
            leg.on_answered = partial(self._sip_answered, line)
            leg.on_ended = partial(self._sip_ended, line)

    # ---------- audio ----------
    # Straight copies. Both sides are already 48 kHz mono int16, and both sides
    # tolerate being fed nothing (each inserts its own silence).

    def _tg_to_sip(self, pcm: bytes):
        leg = self._active
        if leg is not None:
            leg.push_pcm(pcm)

    def _sip_to_tg(self, line: str, pcm: bytes):
        if self.legs.get(line) is self._active:
            self.tg.push_pcm(pcm)

    # ---------- cards ----------

    def line_ids(self) -> list[str]:
        return list(self.legs)

    def describe_lines(self) -> str:
        rows = []
        for line, leg in self.legs.items():
            card = self.cards.get(line) or {}
            rows.append(f"line {line}: {card.get('msisdn') or 'number unknown'} · {leg.user} · "
                        f"{'registered' if leg.registered else 'NOT registered'} · "
                        f"answered by {card.get('answerer') or 'nobody'}")
        return "\n".join(rows) or "No cards are configured."

    # ---------- outbound ----------

    async def place_call(self, number: str, line: str, caller: int) -> str:
        if self.tg.active:
            return "A call is already in progress."
        leg = self.legs.get(line)
        if leg is None:
            return f"Line {line} is not one of my cards. Try /lines."
        if not leg.registered:
            return f"Line {line} is not registered with the gateway right now."
        self._pending_outbound = (line, number)
        self._session = {"direction": "out", "line": line, "number": number,
                         "who": caller, "started": time.time(), "answered": None}
        log.info("outbound: ringing %s before dialling %s on line %s", caller, number, line)
        try:
            ringing = await self.tg.place_call(caller)
        except Exception:
            self._pending_outbound = None
            raise
        if not ringing:
            self._pending_outbound = None
            return "Could not ring you on Telegram."
        return f"Calling you now — answer, and I'll dial {number} on line {line}."

    # ---------- inbound ----------

    def _sip_incoming(self, line: str, peer: str):
        """Runs on a PJSIP thread; hop back onto the loop to touch Telethon."""
        asyncio.run_coroutine_threadsafe(self._ring_answerer(line, peer), self.loop)

    def _card_label(self, line: str) -> str:
        number = (self.cards.get(line) or {}).get("msisdn")
        return f"{number} (line {line})" if number else f"line {line}"

    async def _ring_answerer(self, line: str, peer: str):
        who = (self.cards.get(line) or {}).get("answerer")
        number = _caller_number(peer)
        if self.tg.active:
            log.info("line %s: call from %s while busy — leaving it to ring elsewhere", line, peer)
            if who:
                await self._announce(who, f"Missed call from {number} on "
                                          f"{self._card_label(line)} — you were already talking.")
            return
        if not who:
            log.warning("line %s: call from %s but no answerer is configured", line, peer)
            return
        log.info("line %s: call from %s — ringing %s on Telegram", line, peer, who)
        # The Telegram call only says who the *userbot* is. Without this the
        # answerer has no idea who is actually calling until they pick up.
        await self._announce(who, f"Incoming call from {number} on "
                                  f"{self._card_label(line)} — ringing you now.")
        self._inbound = (line, peer)
        self._session = {"direction": "in", "line": line, "number": _caller_number(peer),
                         "who": who, "started": time.time(), "answered": None}
        try:
            ringing = await self.tg.place_call(who)
        except Exception:
            self._inbound = None
            raise
        if not ringing:
            self._inbound = None
            log.warning("could not reach %s; other extensions keep ringing", who)

    # ---------- joins ----------

    async def _tg_connected(self):
        """They picked up. Now, and only now, involve the SIP side."""
        if self._pending_outbound:
            (line, number), self._pending_outbound = self._pending_outbound, None
            leg = self.legs.get(line)
            if leg is None:
                await self.tg.hangup()
                return
            try:
                leg.dial(number)
            except Exception as e:  # noqa
                log.error("line %s: SIP dial failed: %s", line, e)
                await self.tg.hangup()
                return
            self._active = leg
            if self._session:
                self._session["bridged"] = True
            return
        if self._inbound:
            (line, _peer), self._inbound = self._inbound, None
            leg = self.legs.get(line)
            if leg is not None:
                leg.answer()
                self._active = leg
                if self._session:
                    self._session["bridged"] = True

    def _sip_answered(self, line: str):
        """The far end picked up — the only honest start of the conversation."""
        if self.legs.get(line) is not self._active:
            return
        if self._session and not self._session["answered"]:
            self._session["answered"] = time.time()

    async def _tg_ended(self):
        if self._tearing_down:
            return
        self._tearing_down = True
        session, self._session = self._session, None
        try:
            self._pending_outbound = None
            inbound, self._inbound = self._inbound, None
            leg, self._active = self._active, None
            if leg is not None:
                leg.hangup()
            elif inbound:
                # Declined, or never answered. The SIP call is still only
                # ringing, so leave it alone: every other extension is ringing
                # too, and hanging up here cuts the caller off after one ring.
                log.info("line %s: nobody took the Telegram call — the caller keeps ringing",
                         inbound[0])
        finally:
            self._tearing_down = False
        if session:
            await self._report(session)

    # ---------- call summary ----------

    @staticmethod
    def _summary(session: dict) -> str:
        began = time.strftime("%H:%M:%S", time.localtime(session["started"]))
        way = "outgoing" if session["direction"] == "out" else "incoming"
        head = f"{session['number']} · {way} · line {session['line']}"
        answered = session["answered"]
        if answered:
            return (f"Call ended\n{head}\n"
                    f"Started {began}, connected after {_span(answered - session['started'])}\n"
                    f"Talked for {_span(time.time() - answered)}")
        rang = _span(time.time() - session["started"])
        if not session.get("bridged"):
            # Never reached the SIM at all, which reads very differently from
            # the far end letting it ring.
            missed = ("you did not pick up, so I never dialled"
                      if session["direction"] == "out" else "nobody took it here")
            return f"Not connected\n{head}\nRang at {began} for {rang} — {missed}"
        return f"No answer\n{head}\nRang at {began} for {rang}"

    async def _announce(self, who: int, text: str):
        """A chat message alongside the call itself. Awaited rather than fired
        off: it costs a few hundred milliseconds against a sixty second ring,
        and this way it lands before the phone starts buzzing."""
        try:
            await self.tg.client.send_message(who, text)
        except Exception as e:  # noqa
            log.warning("could not message %s: %s", who, e)

    async def _report(self, session: dict):
        """Tell whoever was on the call how it went. A missed inbound call is
        worth saying too — it is the only trace the SIM rang at all."""
        who = session.get("who")
        if who:
            await self._announce(who, self._summary(session))

    def _sip_ended(self, line: str):
        leg = self.legs.get(line)
        if leg is self._active:
            self._active = None
            self._teardown_tg()
            return
        if self._inbound and self._inbound[0] == line:
            # The caller gave up, or another extension took it, while we were
            # still ringing the answerer. Stop ringing them.
            self._inbound = None
            self._teardown_tg()

    def _teardown_tg(self):
        if self._tearing_down:
            return
        asyncio.run_coroutine_threadsafe(self._hangup_tg(), self.loop)

    async def _hangup_tg(self):
        self._pending_outbound = None
        self._inbound = None
        await self.tg.hangup()

    # ---------- commands ----------

    def send_dtmf(self, digits: str) -> str:
        leg = self._active
        if leg is None:
            return "No call in progress."
        clean = "".join(c for c in digits if c in "0123456789*#ABCD")
        if not clean:
            return "Digits must be 0-9, * or #."
        try:
            leg.send_dtmf(clean)
        except Exception as e:  # noqa
            return f"Could not send DTMF: {e}"
        return f"Sent {clean}."

    async def hangup(self) -> str:
        if not self.tg.active:
            return "No call in progress."
        await self.tg.hangup()
        return "Hung up."
