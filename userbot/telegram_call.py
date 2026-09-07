"""
telegram_call.py - one Telegram 1-on-1 voice call, as a plain audio pipe.

Telethon carries the MTProto signaling (request/accept, DH exchange, endpoints);
ntgcalls is the WebRTC/SRTP stack that actually moves audio. The high-level
py-tgcalls wrapper does not expose raw PCM for private calls, so this talks to
the native pybind11 bindings.

Audio is 48 kHz mono int16 LE in both directions, in 10 ms frames of 480 samples
(960 bytes). 20 ms is a common and wrong assumption that breaks send_external_frame.

THE THREE RULES. Break any of them and the call connects with no audio, which
looks like a network problem and is not:

  1. Ordering. create_p2p_call -> CAPTURE source -> (DH) -> connect_p2p ->
     PLAYBACK source -> unmute -> resume. PLAYBACK attached before connect_p2p
     never delivers a frame.
  2. Inbound frames arrive on the MICROPHONE device with mode=PLAYBACK. That
     reads backwards; it is what the library does.
  3. Outbound must never stop. The sender pushes a frame every 10 ms from the
     moment the call is up, silence included. Going quiet does not merely mute
     us - the inbound direction never opens, and a few seconds of it makes
     Telegram discard the call.

Rules 1 and 2 and the frame geometry are transcribed from a working
implementation (github.com/TxPKev/p2p-offline-ai-telegram-bridge, discussed in
pytgcalls/ntgcalls#44); they are community findings rather than documented API,
so treat a silent call as "check these first".
"""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time

import ntgcalls
from telethon import TelegramClient, events
from telethon.tl.functions.messages import GetDhConfigRequest
from telethon.tl.functions.phone import (
    AcceptCallRequest,
    ConfirmCallRequest,
    DiscardCallRequest,
    RequestCallRequest,
    SendSignalingDataRequest,
)
from telethon.tl.types import (
    InputPhoneCall,
    InputUser,
    PhoneCall,
    PhoneCallAccepted,
    PhoneCallDiscarded,
    PhoneCallDiscardReasonHangup,
    PhoneCallProtocol,
    PhoneCallRequested,
    PhoneCallWaiting,
    UpdatePhoneCall,
    UpdatePhoneCallSignalingData,
)

log = logging.getLogger("userbot.tgcall")

SAMPLE_RATE = 48_000
CHANNELS = 1
FRAME_SAMPLES = 480                     # 10 ms
FRAME_BYTES = FRAME_SAMPLES * 2         # int16 mono
FRAME_SECONDS = FRAME_SAMPLES / SAMPLE_RATE
SILENCE = bytes(FRAME_BYTES)


def _quiet_frames_for_dead_calls(loop: asyncio.AbstractEventLoop):
    """Stop asyncio complaining about the last frame of every call.

    Rule 3 above means the sender is still pushing frames at the instant a call
    ends, and ntgcalls answers each send with an asyncio Future nobody waits on.
    Once the peer hangs up it destroys the connection, so those last futures
    complete with ConnectionNotFound and asyncio logs an ERROR traceback for
    each — a race that cannot be avoided and means nothing. Retrieving them
    instead would cost a cross-thread callback per frame, a hundred a second.

    Only this exact combination is dropped; anything else still surfaces.
    """
    inherited = loop.get_exception_handler()

    def handler(active_loop, context):
        exc = context.get("exception")
        if (isinstance(exc, ntgcalls.ConnectionNotFound)
                and "never retrieved" in (context.get("message") or "")):
            log.debug("frame landed after the call ended: %s", exc)
            return
        if inherited is not None:
            inherited(active_loop, context)
        else:
            active_loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


def _resolve(future, deadline: float = 5.0):
    """ntgcalls methods may hand back a Future. Wait it out on a worker thread —
    it needs the event loop free to make progress, so never do this inline."""
    if future is None or not hasattr(future, "done"):
        return future
    limit = time.monotonic() + deadline
    while not future.done():
        if time.monotonic() > limit:
            raise TimeoutError(f"ntgcalls future timed out after {deadline:.0f}s")
        time.sleep(0.001)
    return future.result()


def _audio_source() -> "ntgcalls.MediaDescription":
    """Raw-PCM media description. Both directions use the microphone slot; see rule 2."""
    return ntgcalls.MediaDescription(
        microphone=ntgcalls.AudioDescription(
            media_source=ntgcalls.MediaSource.EXTERNAL,
            sample_rate=SAMPLE_RATE,
            channel_count=CHANNELS,
            input="",
        ),
    )


def _rtc_servers(call: PhoneCall) -> list:
    """Telegram's endpoint list -> ntgcalls RTCServer objects."""
    servers = []
    for conn in (getattr(call, "connections", None) or []):
        try:
            servers.append(ntgcalls.RTCServer(
                id=conn.id,
                ipv4=getattr(conn, "ip", None) or getattr(conn, "ipv4", ""),
                ipv6=getattr(conn, "ipv6", "") or "",
                port=conn.port,
                username=getattr(conn, "username", None),
                password=getattr(conn, "password", None),
                turn=getattr(conn, "turn", False),
                stun=getattr(conn, "stun", False),
                tcp=getattr(conn, "tcp", False),
                peer_tag=getattr(conn, "peer_tag", None),
            ))
        except Exception as e:  # noqa
            log.warning("skipping unusable connection endpoint: %s", e)
    return servers


class _Sender:
    """Paces outbound frames at exactly 10 ms, filling with silence when the
    bridge has nothing. This thread running is what keeps the call alive (rule 3)."""

    def __init__(self, ntg, call_id):
        self._ntg, self._call_id = ntg, call_id
        self._q: "queue.Queue[bytes]" = queue.Queue(maxsize=200)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"tg-out-{call_id}")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def push(self, pcm: bytes):
        """Queue 48 kHz mono int16. Anything not frame-aligned is padded."""
        for off in range(0, len(pcm), FRAME_BYTES):
            frame = pcm[off:off + FRAME_BYTES]
            if len(frame) < FRAME_BYTES:
                frame += bytes(FRAME_BYTES - len(frame))
            try:
                self._q.put_nowait(frame)
            except queue.Full:
                # Better to drop the oldest audio than to drift further behind.
                try:
                    self._q.get_nowait()
                    self._q.put_nowait(frame)
                except queue.Empty:
                    pass

    def _run(self):
        next_tick = time.perf_counter()
        while not self._stop.is_set():
            now = time.perf_counter()
            if now < next_tick:
                slack = next_tick - now
                if slack > 0.001:
                    time.sleep(slack - 0.001)
                while time.perf_counter() < next_tick:   # last ms: sleep is too coarse
                    pass
            next_tick += FRAME_SECONDS
            try:
                frame = self._q.get_nowait()
            except queue.Empty:
                frame = SILENCE
            try:
                self._ntg.send_external_frame(
                    self._call_id, ntgcalls.StreamDevice.MICROPHONE, frame,
                    ntgcalls.FrameData(int(time.monotonic() * 1000), 0, 0, 0))
            except Exception as e:  # noqa
                log.warning("send_external_frame failed: %s", e)
                return


class TelegramCallLeg:
    """The Telegram half of a bridged call.

    Hand it callbacks and it will hand you 48 kHz PCM:
      on_pcm(bytes)   - inbound audio from the peer
      on_connected()  - media is flowing both ways
      on_ended()      - the call is gone; tear down the other leg
    """

    def __init__(self, client: TelegramClient, owners):
        self.client = client
        # Every account allowed to drive the bridge. Permissions are flat: any
        # of them may be called, and a call from any of them is taken.
        self.owners = [int(o) for o in owners if int(o)]
        self.peer_id: int | None = None     # who this call is with
        self.on_pcm = None
        self.on_connected = None
        self.on_ended = None

        self._ntg = ntgcalls.NTgCalls()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sender: _Sender | None = None

        # Telegram's call id and ntgcalls' internal id are different numbers.
        self._call_id = None            # Telegram phone call id
        self._access_hash = None
        self._ntg_id = None             # ntgcalls handle
        self._connected = False
        self._queued_signaling: list[bytes] = []
        self._signaling_ready = False
        self._last_warning: str | None = None
        self._started_at: float | None = None

    # ---------- lifecycle ----------

    def install(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        _quiet_frames_for_dead_calls(loop)
        self._register_callbacks()
        self.client.add_event_handler(self._on_update, events.Raw(UpdatePhoneCall))
        self.client.add_event_handler(self._on_signaling,
                                      events.Raw(UpdatePhoneCallSignalingData))

    @property
    def active(self) -> bool:
        return self._call_id is not None

    def _warn_once(self, message: str):
        """Audio callbacks fire a hundred times a second, so a broken frame path
        would otherwise bury every other line in the log."""
        if message != self._last_warning:
            self._last_warning = message
            log.warning("%s", message)

    async def _ntg_call(self, method, *args, deadline: float = 5.0, **kwargs):
        return await asyncio.get_running_loop().run_in_executor(
            None, lambda: _resolve(method(*args, **kwargs), deadline))

    def _register_callbacks(self):
        @self._ntg.on_frames
        def _frames(uid, mode, device, frames):          # noqa: ARG001
            # Rule 2: inbound is mode=PLAYBACK, and CAPTURE never fires here.
            if mode != ntgcalls.StreamMode.PLAYBACK or not self.on_pcm:
                return
            for frame in frames:
                try:
                    # A Frame is an object (ssrc, data, frame_data), not a buffer:
                    # bytes(frame) raises, and losing every frame this way is a
                    # silent one-way call, not an obvious failure.
                    self.on_pcm(bytes(frame.data))
                except Exception as e:  # noqa
                    self._warn_once(f"inbound frame handler failed: {e}")

        @self._ntg.on_signaling
        def _signaling(chat_id, data):                   # noqa: ARG001
            # Fires on a native thread; MTProto has to happen on the asyncio loop.
            if self._loop and self._call_id is not None:
                asyncio.run_coroutine_threadsafe(self._relay(bytes(data)), self._loop)

        @self._ntg.on_connection_change
        def _conn(chat_id, info):                        # noqa: ARG001
            state = getattr(info, "state", None)
            log.info("telegram call transport: %s", str(state).rsplit(".", 1)[-1])

    async def _relay(self, data: bytes):
        try:
            await self.client(SendSignalingDataRequest(
                peer=InputPhoneCall(self._call_id, self._access_hash), data=data))
        except Exception as e:  # noqa
            log.warning("signaling relay failed: %s", e)

    # ---------- outbound audio ----------

    def push_pcm(self, pcm: bytes):
        """Feed the peer 48 kHz mono int16. Silence is inserted automatically when
        nothing is pushed, so the bridge may simply stop during ringing."""
        if self._sender:
            self._sender.push(pcm)

    # ---------- placing a call ----------

    async def place_call(self, peer_id: int) -> bool:
        """Ring one of the authorised accounts. The DH half here is the CALLER
        side: we publish g_a_hash up front and only reveal g_a once they accept.

        Unlike the answering path below, this direction has no published working
        reference — if a placed call connects silently, the DH exchange is the
        first place to instrument.
        """
        if self.active:
            log.warning("a call is already in progress")
            return False
        peer_id = int(peer_id)
        if peer_id not in self.owners:
            log.warning("refusing to call %s — not an authorised account", peer_id)
            return False
        try:
            peer = await self.client.get_input_entity(peer_id)
        except Exception as e:  # noqa
            log.error("cannot resolve account %s: %s", peer_id, e)
            return False
        self.peer_id = peer_id
        try:
            return await self._place_call(peer)
        except Exception:
            # A half-built call leaves an ntgcalls session behind, and
            # create_p2p_call refuses a second one for the same peer — so a
            # retry would fail for a different reason than the first attempt.
            await self._drop_session()
            raise

    async def _place_call(self, peer) -> bool:
        self._ntg_id = await self._ntg_call(self._ntg.create_p2p_call, self.peer_id) \
            or self.peer_id
        await self._ntg_call(self._ntg.set_stream_sources, self._ntg_id,
                             ntgcalls.StreamMode.CAPTURE, _audio_source())

        dh = await self.client(GetDhConfigRequest(version=0, random_length=256))
        # init_exchange(user_id, dh_config, g_a_hash) — the third argument is
        # required, not optional. None means "I am the caller", and what comes
        # back is our own g_a_hash; passing the peer's hash is the answering
        # side (_accept), which gets g_b back instead.
        g_a_hash = await self._ntg_call(
            self._ntg.init_exchange, self._ntg_id,
            ntgcalls.DhConfig(g=dh.g, p=dh.p, random=dh.random), None)

        proto = ntgcalls.NTgCalls.get_protocol()
        res = await self.client(RequestCallRequest(
            user_id=InputUser(peer.user_id, peer.access_hash) if hasattr(peer, "user_id") else peer,
            random_id=int(time.time() * 1000) & 0x7FFFFFFF,
            g_a_hash=g_a_hash,
            protocol=PhoneCallProtocol(
                min_layer=proto.min_layer, max_layer=proto.max_layer,
                udp_p2p=proto.udp_p2p, udp_reflector=proto.udp_reflector,
                library_versions=list(proto.library_versions)),
        ))
        call = res.phone_call
        self._call_id, self._access_hash = call.id, call.access_hash
        log.info("calling %s (call_id=%s)", self.peer_id, call.id)
        return True

    # ---------- answering a call ----------

    async def _accept(self, req: PhoneCallRequested):
        if int(req.admin_id) not in self.owners:
            log.warning("refusing call from %s (authorised: %s)",
                        req.admin_id, ", ".join(str(o) for o in self.owners))
            await self._discard(req.id, req.access_hash)
            return
        self._call_id, self._access_hash = req.id, req.access_hash
        self.peer_id = int(req.admin_id)

        # Ordering, rule 1: the session and the outbound source exist before any
        # key material is exchanged.
        self._ntg_id = await self._ntg_call(self._ntg.create_p2p_call, self.peer_id) \
            or self.peer_id
        await self._ntg_call(self._ntg.set_stream_sources, self._ntg_id,
                             ntgcalls.StreamMode.CAPTURE, _audio_source())

        dh = await self.client(GetDhConfigRequest(version=0, random_length=256))
        g_b = await self._ntg_call(
            self._ntg.init_exchange, self._ntg_id,
            ntgcalls.DhConfig(g=dh.g, p=dh.p, random=dh.random), req.g_a_hash)

        proto = ntgcalls.NTgCalls.get_protocol()
        res = await self.client(AcceptCallRequest(
            peer=InputPhoneCall(req.id, req.access_hash), g_b=g_b,
            protocol=PhoneCallProtocol(
                min_layer=proto.min_layer, max_layer=proto.max_layer,
                udp_p2p=proto.udp_p2p, udp_reflector=proto.udp_reflector,
                library_versions=list(proto.library_versions)),
        ))
        log.info("accepted call %s, waiting for confirmation", req.id)
        # Normally still phoneCallWaiting here — the caller has yet to confirm —
        # but take the live call if it is already there rather than assume.
        await self._go_live_if_active(res)

    async def _confirm_outgoing(self, call: PhoneCallAccepted):
        """Caller side: they answered and sent g_b, so reveal g_a and confirm."""
        # exchange_keys hands back AuthParams(g_a_or_b, key_fingerprint); on this
        # side g_a_or_b is our g_a, and the fingerprint is computed from the
        # shared key, so both go straight into ConfirmCall.
        params = await self._ntg_call(
            self._ntg.exchange_keys, self._ntg_id, call.g_b, 0)
        proto = ntgcalls.NTgCalls.get_protocol()
        res = await self.client(ConfirmCallRequest(
            peer=InputPhoneCall(call.id, call.access_hash),
            g_a=bytes(params.g_a_or_b),
            key_fingerprint=params.key_fingerprint,
            protocol=PhoneCallProtocol(
                min_layer=proto.min_layer, max_layer=proto.max_layer,
                udp_p2p=proto.udp_p2p, udp_reflector=proto.udp_reflector,
                library_versions=list(proto.library_versions)),
        ))
        log.info("confirmed call %s", call.id)
        # confirmCall's own result carries the live call (endpoints, fingerprint).
        # Waiting for an updatePhoneCall instead can mean waiting forever: the
        # callee has already answered, so no media means Telegram drops the call
        # as "disconnected" some twenty seconds later.
        await self._go_live_if_active(res)

    async def _go_live_if_active(self, result):
        """Open media from an accept/confirm reply, if it already carries the
        live call. Anything else means the handshake is still in flight and the
        updatePhoneCall we also listen for is the one that will bring it."""
        call = getattr(result, "phone_call", None)
        if isinstance(call, PhoneCall):
            await self._go_live(call)
        else:
            log.info("call handshake still pending (%s)", type(call).__name__)

    async def _go_live(self, call: PhoneCall):
        """Both sides agreed: finish the handshake and open the media path."""
        if self._connected:
            return          # Telegram repeats this update; a second connect_p2p raises
        self._connected = True
        log.info("call %s agreed; opening media", call.id)
        try:
            # The answering side still owes exchange_keys; the caller already did it
            # in _confirm_outgoing, and repeating it is harmless enough to skip.
            if getattr(call, "g_a_or_b", None) is not None:
                try:
                    await self._ntg_call(
                        self._ntg.exchange_keys, self._ntg_id,
                        call.g_a_or_b, call.key_fingerprint)
                except Exception as e:  # noqa
                    log.debug("exchange_keys already done: %s", e)

            servers = _rtc_servers(call)
            if not servers:
                raise RuntimeError("Telegram offered no connection endpoints")
            proto = ntgcalls.NTgCalls.get_protocol()
            await self._ntg_call(self._ntg.connect_p2p, self._ntg_id, servers,
                                 list(proto.library_versions), True, deadline=12.0)

            self._signaling_ready = True
            for queued in self._queued_signaling:
                await self._ntg_call(self._ntg.send_signaling, self._ntg_id, queued)
            self._queued_signaling.clear()

            # Rule 1: PLAYBACK only now, or inbound audio never arrives.
            await self._ntg_call(self._ntg.set_stream_sources, self._ntg_id,
                                 ntgcalls.StreamMode.PLAYBACK, _audio_source())
            await self._ntg_call(self._ntg.unmute, self._ntg_id)
            await self._ntg_call(self._ntg.resume, self._ntg_id)

            # Rule 3: start pushing immediately, silence included.
            self._sender = _Sender(self._ntg, self._ntg_id)
            self._sender.start()
            self._started_at = time.monotonic()

            log.info("telegram call live (call_id=%s)", self._call_id)
            if self.on_connected:
                await _maybe_await(self.on_connected())
        except Exception as e:  # noqa
            log.error("could not bring the call up: %s", e)
            await self.hangup()

    # ---------- teardown ----------

    async def _discard(self, call_id=None, access_hash=None):
        # reason is a required TLObject, so None fails at serialisation time and
        # the request never leaves. Swallowing that quietly is how the other leg
        # hanging up left the call still ringing on the owner's phone.
        started = self._started_at
        try:
            await self.client(DiscardCallRequest(
                peer=InputPhoneCall(call_id or self._call_id,
                                    access_hash or self._access_hash),
                duration=int(time.monotonic() - started) if started else 0,
                reason=PhoneCallDiscardReasonHangup(), connection_id=0))
        except Exception as e:  # noqa
            log.warning("could not discard call %s: %s", call_id or self._call_id, e)

    async def hangup(self):
        if not self.active:
            return
        await self._discard()
        await self._cleanup()

    async def _drop_session(self):
        """Forget the call without telling the bridge — for an attempt that never
        became a call, where tearing down the other leg would be wrong."""
        if self._sender:
            self._sender.stop()
            self._sender = None
        # Take the handle before stopping it: the SIP side and the Telegram side
        # can both start tearing down at once, and the loser would otherwise
        # stop a connection ntgcalls has already forgotten.
        ntg_id, self._ntg_id = self._ntg_id, None
        if ntg_id is not None:
            try:
                await self._ntg_call(self._ntg.stop, ntg_id)
            except Exception as e:  # noqa
                log.debug("ntgcalls stop: %s", e)
        self._call_id = self._access_hash = self.peer_id = None
        self._connected = self._signaling_ready = False
        self._queued_signaling.clear()
        self._last_warning = None
        self._started_at = None

    async def _cleanup(self):
        await self._drop_session()
        if self.on_ended:
            await _maybe_await(self.on_ended())

    # ---------- telethon plumbing ----------

    async def _on_update(self, update: UpdatePhoneCall):
        call = getattr(update, "phone_call", None)
        if call is None:
            return
        try:
            if isinstance(call, PhoneCallRequested):
                await self._accept(call)
            elif isinstance(call, PhoneCallWaiting):
                # receive_date is the one field that says whether the callee's
                # device was actually reached: unset means it is ringing nowhere.
                log.info("call %s waiting — peer device %s", call.id,
                         "is ringing" if call.receive_date else "not reached yet")
            elif isinstance(call, PhoneCallAccepted):
                log.info("call %s accepted by the peer; confirming", call.id)
                await self._confirm_outgoing(call)
            elif isinstance(call, PhoneCall):
                await self._go_live(call)
            elif isinstance(call, PhoneCallDiscarded):
                if self._call_id == call.id:
                    log.info("call %s ended (%s) after %ss", call.id, call.reason,
                             getattr(call, "duration", 0) or 0)
                    await self._cleanup()
            else:
                log.info("call update ignored: %s", type(call).__name__)
        except Exception as e:  # noqa
            log.exception("call update handling failed: %s", e)

    async def _on_signaling(self, update: UpdatePhoneCallSignalingData):
        if update.phone_call_id != self._call_id:
            return
        data = bytes(update.data)
        if not self._signaling_ready:
            # Telegram starts relaying before connect_p2p exists to receive it.
            self._queued_signaling.append(data)
            log.info("peer is signalling (%s packet(s) queued)", len(self._queued_signaling))
            return
        try:
            await self._ntg_call(self._ntg.send_signaling, self._ntg_id, data)
        except Exception as e:  # noqa
            log.warning("send_signaling failed: %s", e)


async def _maybe_await(value):
    if asyncio.iscoroutine(value):
        await value
