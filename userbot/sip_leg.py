"""
sip_leg.py - the gateway half of a bridged call, as a plain audio pipe.

The userbot registers as an ordinary external SIP account. Nothing in the engine
image has to change for that: the inbound dialplan already rings every
`sip.external[]` account alongside the WebRTC user, and an INVITE sent from such
an account lands in `from-local`, which hairpins it to the IMS trunk. So both
directions already exist; we just have to be a normal SIP phone.

Sample rate is the reason PJSUA2 is here rather than a hand-rolled RTP socket.
Setting the endpoint clock to 48 kHz makes PJSIP hand us 48 kHz PCM in the audio
port callbacks - exactly what Telegram wants - while it transcodes to ulaw 8 kHz
on the wire itself. No resampling code of our own, which matters because Python
3.13 dropped `audioop`. Nothing is lost by the narrowband wire format: the IMS
trunk is `disallow=all / allow=amr`, so the ceiling is narrowband regardless.

DTMF is likewise PJSUA2's problem: dialDtmf takes the whole digit string and
handles inter-digit timing.

Answering behaviour matters for multi-extension setups. On an inbound call we
send 180 Ringing and wait; the call is only answered once the Telegram leg is
up. Answering immediately would stop every other extension ringing - the browser
softphone, MicroSIP - and quietly make the userbot the only phone in the house.
"""
from __future__ import annotations

import logging
import threading

import pjsua2 as pj

log = logging.getLogger("userbot.sip")

SAMPLE_RATE = 48_000
CHANNELS = 1
FRAME_SAMPLES = 480                     # 10 ms, matching the Telegram side
FRAME_BYTES = FRAME_SAMPLES * 2


class _BridgePort(pj.AudioMediaPort):
    """A virtual sound device. PJSIP pulls outbound frames from us and pushes
    inbound ones in, both already at 48 kHz because of the endpoint clock rate."""

    def __init__(self, on_pcm):
        super().__init__()
        self._on_pcm = on_pcm
        self._out = bytearray()
        self._lock = threading.Lock()

    def queue_outbound(self, pcm: bytes):
        with self._lock:
            self._out.extend(pcm)
            # Never let a stalled far end grow this without bound; a quarter
            # second of backlog is already more delay than a call can carry.
            limit = FRAME_BYTES * 25
            if len(self._out) > limit:
                del self._out[:len(self._out) - limit]

    def onFrameRequested(self, frame):
        """PJSIP wants audio to send to the gateway."""
        frame.type = pj.PJMEDIA_FRAME_TYPE_AUDIO
        with self._lock:
            if len(self._out) >= FRAME_BYTES:
                chunk = bytes(self._out[:FRAME_BYTES])
                del self._out[:FRAME_BYTES]
            else:
                chunk = bytes(FRAME_BYTES)      # silence keeps the stream regular
        frame.buf = pj.ByteVector(chunk)
        frame.size = len(chunk)

    def onFrameReceived(self, frame):
        """Audio from the gateway, headed for Telegram."""
        if self._on_pcm and frame.size:
            try:
                self._on_pcm(bytes(frame.buf))
            except Exception as e:  # noqa
                log.warning("inbound SIP frame handler failed: %s", e)


class _Call(pj.Call):
    def __init__(self, acc, leg, call_id=pj.PJSUA_INVALID_ID):
        super().__init__(acc, call_id)
        self._leg = leg

    def _bind_audio(self):
        """Join every active audio media on this call to the bridge port."""
        info = self.getInfo()
        for i, media in enumerate(info.media):
            if (media.type == pj.PJMEDIA_TYPE_AUDIO
                    and media.status == pj.PJSUA_CALL_MEDIA_ACTIVE):
                self._leg._attach_media(self.getAudioMedia(i))

    def onCallState(self, prm):                              # noqa: ARG002
        info = self.getInfo()
        log.info("SIP call state: %s", info.stateText)
        if info.state == pj.PJSIP_INV_STATE_CONFIRMED:
            # An answered inbound call renegotiates media on our own 200 OK, and
            # onCallMediaState does not necessarily fire again for it. Binding
            # once more here keeps the bridge port off the early media it
            # attached to while ringing — whichever direction was left on the
            # old session went silent for the rest of the call.
            self._bind_audio()
            # The far end actually picked up. Media attaches earlier than this,
            # during ringback, so this is the only honest start of the call.
            self._leg._on_answered(self)
        elif info.state == pj.PJSIP_INV_STATE_DISCONNECTED:
            self._leg._on_disconnected(self)

    def onCallMediaState(self, prm):                         # noqa: ARG002
        self._bind_audio()

    def onDtmfDigit(self, prm):
        log.info("DTMF from the far end: %s", prm.digit)


_endpoint: "pj.Endpoint | None" = None
_endpoint_lock = threading.Lock()


def shared_endpoint() -> "pj.Endpoint":
    """The one PJSUA2 endpoint this process gets.

    PJSUA2 is a singleton: a second libCreate() raises PJ_EEXISTS, and because
    that surfaces as a C++ exception it takes the interpreter with it rather
    than raising in Python. Every card's account therefore shares this endpoint
    and its UDP transport, which is also why their usernames have to differ --
    an account is matched by its `sip:user@host` identity.
    """
    global _endpoint
    with _endpoint_lock:
        if _endpoint is not None:
            return _endpoint
        ep = pj.Endpoint()
        ep.libCreate()

        cfg = pj.EpConfig()
        # The whole point: give PJSIP a 48 kHz clock and it resamples to the
        # negotiated wire codec itself, so our frames match Telegram exactly.
        cfg.medConfig.clockRate = SAMPLE_RATE
        cfg.medConfig.sndClockRate = SAMPLE_RATE
        cfg.medConfig.channelCount = CHANNELS
        cfg.medConfig.audioFramePtime = 10
        cfg.uaConfig.userAgent = "vowifi-userbot"
        cfg.logConfig.level = 3
        ep.libInit(cfg)

        transport = pj.TransportConfig()
        transport.port = 0                      # any free local port
        ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, transport)
        ep.libStart()
        # No sound card in a container, and we do not want one: audio only ever
        # travels between our bridge ports and the calls.
        ep.audDevManager().setNullDev()
        _endpoint = ep
        return ep


def shutdown_endpoint():
    """Tear the whole stack down, once every leg has stopped."""
    global _endpoint
    with _endpoint_lock:
        if _endpoint is None:
            return
        try:
            _endpoint.libDestroy()
        except Exception as e:  # noqa
            log.debug("SIP endpoint shutdown: %s", e)
        _endpoint = None


class _Account(pj.Account):
    def __init__(self, leg):
        super().__init__()
        self._leg = leg

    def onRegState(self, prm):                               # noqa: ARG002
        info = self.getInfo()
        self._leg.registered = bool(info.regIsActive)
        log.info("SIP registration: %s (%s)",
                 "up" if info.regIsActive else "down", info.regStatus)

    def onIncomingCall(self, prm):
        self._leg._on_incoming(prm.callId)


class SipLeg:
    """One registered SIP account that can place and answer a single call.

    Callbacks:
      on_pcm(bytes)      - audio from the gateway (48 kHz mono int16)
      on_incoming(peer)  - an inbound call is ringing; answer() to take it
      on_connected()     - media is up
      on_answered()      - the far end picked up (later than on_connected)
      on_ended()         - the SIP call is gone
    """

    def __init__(self, user: str, password: str, domain: str, port: int = 5060):
        self.user, self.password, self.domain, self.port = user, password, domain, port
        self.registered = False
        self.on_pcm = None
        self.on_incoming = None
        self.on_connected = None
        self.on_answered = None
        self.on_ended = None

        self._ep: pj.Endpoint | None = None
        self._acc: _Account | None = None
        self._call: _Call | None = None
        self._port: _BridgePort | None = None
        self._media: pj.AudioMedia | None = None

    # ---------- lifecycle ----------

    def start(self):
        self._ep = shared_endpoint()

        acfg = pj.AccountConfig()
        acfg.idUri = f"sip:{self.user}@{self.domain}"
        acfg.regConfig.registrarUri = f"sip:{self.domain}:{self.port}"
        cred = pj.AuthCredInfo("digest", "*", self.user, 0, self.password)
        acfg.sipConfig.authCreds.append(cred)
        self._acc = _Account(self)
        self._acc.create(acfg)
        log.info("SIP account %s@%s registering", self.user, self.domain)

    def stop(self):
        """Drop this card's account. The endpoint is shared, so it outlives us —
        see shutdown_endpoint()."""
        try:
            if self._call:
                self.hangup()
            if self._acc:
                self._acc.shutdown()
        except Exception as e:  # noqa
            log.debug("SIP shutdown: %s", e)
        self._ep = self._acc = self._call = None

    # ---------- audio ----------

    def push_pcm(self, pcm: bytes):
        """Send 48 kHz mono int16 towards the gateway."""
        if self._port:
            self._port.queue_outbound(pcm)

    def _attach_media(self, audio: pj.AudioMedia):
        if self._port is None:
            self._port = _BridgePort(lambda pcm: self.on_pcm and self.on_pcm(pcm))
            fmt = pj.MediaFormatAudio()
            fmt.type = pj.PJMEDIA_TYPE_AUDIO
            fmt.clockRate = SAMPLE_RATE
            fmt.channelCount = CHANNELS
            fmt.bitsPerSample = 16
            fmt.frameTimeUsec = 10_000
            self._port.createPort("tg-bridge", fmt)
        self._media = audio
        audio.startTransmit(self._port)
        self._port.startTransmit(audio)
        log.info("SIP media attached")
        if self.on_connected:
            self.on_connected()

    # ---------- calls ----------

    def dial(self, number: str):
        if self._call:
            raise RuntimeError("a SIP call is already in progress")
        self._call = _Call(self._acc, self)
        prm = pj.CallOpParam(True)
        # The port is not optional here. Every line's Asterisk is on its own
        # host port (5060, 5070, ...), and PJSIP routes an INVITE by its request
        # URI: without one this dials whichever engine holds the default 5060,
        # which then rejects an account it has never heard of.
        target = f"sip:{number}@{self.domain}:{self.port}"
        self._call.makeCall(target, prm)
        log.info("SIP INVITE to %s", target)

    def _on_incoming(self, call_id):
        if self._call:
            log.info("busy — refusing a second inbound call")
            call = _Call(self._acc, self, call_id)
            prm = pj.CallOpParam()
            prm.statusCode = 486                    # Busy Here
            call.hangup(prm)
            return
        self._call = _Call(self._acc, self, call_id)
        info = self._call.getInfo()
        # 180 only. Answering here would silence every other extension; the
        # bridge answers once the owner has picked up on Telegram.
        prm = pj.CallOpParam()
        prm.statusCode = 180
        self._call.answer(prm)
        peer = info.remoteUri
        log.info("inbound SIP call from %s — ringing", peer)
        if self.on_incoming:
            self.on_incoming(peer)

    def answer(self):
        if not self._call:
            return
        # CallOpParam(True), as dial() uses: the bare constructor zeroes the
        # call settings, audioCount included, which is not what you want to
        # answer a call with. The 180 above is fine bare — it carries no SDP.
        prm = pj.CallOpParam(True)
        prm.statusCode = 200
        self._call.answer(prm)
        log.info("answered the SIP call")

    def send_dtmf(self, digits: str):
        """PJSUA2 paces multi-digit strings itself, which is why /dtmf 1234 works."""
        if not self._call:
            raise RuntimeError("no active call")
        self._call.dialDtmf(digits)
        log.info("sent DTMF %s", digits)

    def hangup(self):
        if not self._call:
            return
        try:
            self._call.hangup(pj.CallOpParam())
        except Exception as e:  # noqa
            log.debug("SIP hangup: %s", e)

    def _on_answered(self, call):
        if call is not self._call or not self.on_answered:
            return
        self.on_answered()

    def _on_disconnected(self, call):
        if call is not self._call:
            return
        self._call = None
        self._media = None
        log.info("SIP call disconnected")
        if self.on_ended:
            self.on_ended()
