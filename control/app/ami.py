"""
ami.py - Async Asterisk AMI client (per engine instance).

The manager keeps one AmiClient per running instance to: read IMS registration state,
send SMS (AMI MessageSend to the volte_ims endpoint), place calls (Originate), and
receive live events. Incoming call/SMS are primarily delivered via the engine's
notify.py HTTP hooks; AMI events supplement call state.
"""
from __future__ import annotations

import asyncio
import logging

from panoramisk import Manager

log = logging.getLogger("vowifi.ami")


class AmiClient:
    # Hard bounds so a wedged AMI connection can never hang the status poller / API.
    CONNECT_TIMEOUT = 6.0    # login handshake
    ACTION_TIMEOUT = 8.0     # any single AMI action (send_action) response

    def __init__(self, instance_id: str, host: str, port: int, username: str, secret: str,
                 realm: str, msisdn: str = "", smsc: str = ""):
        self.instance_id = str(instance_id)
        self.host = host
        self.port = port
        self.username = username
        self.secret = secret
        self.realm = realm
        self.msisdn = msisdn
        self.smsc = smsc
        self._mgr: Manager | None = None
        self._connected = False
        self._event_cb = None

    async def connect(self):
        self._mgr = Manager(host=self.host, port=self.port,
                            username=self.username, secret=self.secret,
                            ping_delay=15, reconnect_timeout=5)
        try:
            # Bound the login handshake: a half-open TCP (e.g. the container was just
            # recreated on the same IP) must not block the caller indefinitely.
            await asyncio.wait_for(self._mgr.connect(), timeout=self.CONNECT_TIMEOUT)
            self._connected = True
            log.info("AMI connected instance=%s %s:%s", self.instance_id, self.host, self.port)
        except Exception as e:  # noqa  (asyncio.TimeoutError included)
            self._connected = False
            log.warning("AMI connect failed instance=%s: %r", self.instance_id, e)

    async def _action(self, action: dict, timeout: float | None = None):
        """Send an AMI action with a hard timeout. panoramisk's send_action awaits a Future
        that resolves when the matching AMI response arrives; if the connection is wedged
        (socket up but Asterisk not answering, or a reconnect orphaned the in-flight future)
        that Future never resolves. Without this bound a single stuck action hangs the status
        poller AND the /api/instances handler forever. On timeout we mark the client
        disconnected so ami_for() rebuilds it on the next call, and re-raise TimeoutError."""
        try:
            return await asyncio.wait_for(self._mgr.send_action(action),
                                          timeout=timeout or self.ACTION_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("AMI action timed out instance=%s action=%s -> marking disconnected",
                        self.instance_id, action.get("Action"))
            self._connected = False
            raise

    async def close(self):
        if self._mgr:
            try:
                self._mgr.close()
            except Exception:
                pass
        self._connected = False

    @property
    def connected(self):
        return self._connected and self._mgr is not None

    async def registration_state(self) -> str:
        """Return 'Registered' | 'Rejected' | 'Unregistered' | 'unknown'."""
        if not self.connected:
            return "unknown"
        try:
            res = await self._action({"Action": "PJSIPShowRegistrationsDetailed"})
            for msg in (res if isinstance(res, list) else [res]):
                status = (msg.get("Status") or "").strip()
                if status:
                    return status
        except Exception as e:  # noqa
            log.debug("reg state error: %r", e)
        # Fallback: CLI
        try:
            res = await self._action(
                {"Action": "Command", "Command": "pjsip show registrations"})
            text = ""
            for m in (res if isinstance(res, list) else [res]):
                text += str(m.get("Output") or m.get("content") or "")
            if "Registered" in text:
                return "Registered"
            if "Rejected" in text:
                return "Rejected"
            if "Unregistered" in text:
                return "Unregistered"
        except Exception:
            pass
        return "unknown"

    async def send_sms(self, to: str, body: str) -> dict:
        if not self.connected:
            return {"ok": False, "error": "AMI not connected"}
        dest = f"pjsip:volte_ims/{to}@volte_ims"
        frm = f"sip:{self.msisdn or to}@{self.realm}"
        try:
            res = await self._action(
                {"Action": "MessageSend", "To": dest, "From": frm, "Body": body})
            msg = res[0] if isinstance(res, list) else res
            ok = (msg.get("Response") == "Success")
            return {"ok": ok, "detail": msg.get("Message", "")}
        except Exception as e:  # noqa
            return {"ok": False, "error": repr(e)}

    async def originate(self, to: str, from_endpoint: str) -> dict:
        """Place a call: ring from_endpoint (a local endpoint / softphone) and bridge to
        the dialed number over the IMS. Uses a Local channel into from-local."""
        if not self.connected:
            return {"ok": False, "error": "AMI not connected"}
        try:
            res = await self._action({
                "Action": "Originate",
                "Channel": f"PJSIP/{from_endpoint}",
                "Exten": to,
                "Context": "from-local",
                "Priority": "1",
                "CallerID": self.msisdn or "gateway",
                "Async": "true",
            }, timeout=12.0)
            msg = res[0] if isinstance(res, list) else res
            return {"ok": msg.get("Response") == "Success", "detail": msg.get("Message", "")}
        except Exception as e:  # noqa
            return {"ok": False, "error": repr(e)}

    async def hangup_all(self) -> dict:
        if not self.connected:
            return {"ok": False, "error": "AMI not connected"}
        try:
            await self._action({"Action": "Command", "Command": "channel request hangup all"})
            return {"ok": True}
        except Exception as e:  # noqa
            return {"ok": False, "error": repr(e)}
