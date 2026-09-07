"""
spike_echo.py - step 0 of the userbot: does Telegram 1-on-1 audio work at all?

No SIP, no gateway, no bridge. It answers a call from the owner and plays their
own voice back at them, delayed by the buffer. That single test proves the two
things everything else is built on:

  * outbound works  - you hear anything at all
  * inbound works   - what you hear is YOUR voice, not silence

Inbound is the half that historically fails (pytgcalls/ntgcalls#44). If you hear
nothing, the call still "connects" and the logs still look healthy, which is
exactly why this is worth proving before writing the SIP bridge.

Run it, call the userbot account from a normal Telegram client, and talk.

    cd userbot
    cp config.example.json config.json     # fill in api_id / api_hash / phone / owner_id
    python spike_echo.py

First run asks for the login code Telegram sends you. The session is cached
afterwards, and that session file is equivalent to the account.

Telegram Web A negotiates a protocol version ntgcalls does not speak - answer
from a phone or the desktop client.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

from telegram_call import FRAME_BYTES, TelegramCallLeg

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("spike")


def load_config() -> dict:
    import json
    # Same search as main.py: a local file for a laptop spike, then the volume
    # the WebUI writes. The login command the Settings page prints is the second
    # path, and looking only next to this script made that command fail.
    for path in (Path(__file__).parent / "config.json", Path("/data/userbot/config.json")):
        if path.exists():
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    log.error("config.json missing — copy config.example.json, or save the form in Settings")
    sys.exit(1)


class EchoProbe:
    """Counts what actually moved, so the verdict isn't a matter of opinion."""

    def __init__(self):
        self.frames_in = 0
        self.bytes_in = 0
        self.loud_frames = 0
        self.first_frame_at = None
        self.leg: TelegramCallLeg | None = None

    def on_pcm(self, pcm: bytes):
        self.frames_in += 1
        self.bytes_in += len(pcm)
        if self.first_frame_at is None:
            self.first_frame_at = time.monotonic()
            log.info("FIRST INBOUND FRAME (%d bytes) — inbound audio works", len(pcm))
        # Rough loudness: anything above the noise floor means real speech, not
        # a stream of well-formed zeroes (which would still count as "frames").
        if _peak(pcm) > 500:
            self.loud_frames += 1
        if self.leg:
            self.leg.push_pcm(pcm)          # the echo itself

    def report(self) -> str:
        if not self.frames_in:
            return ("NO INBOUND AUDIO. The call connected but on_frames never fired. "
                    "Check, in order: PLAYBACK attached after connect_p2p, attached on "
                    "the microphone slot, and outbound frames flowing the whole time.")
        secs = (time.monotonic() - self.first_frame_at) if self.first_frame_at else 0
        verdict = "PASS" if self.loud_frames > 20 else "frames arrived but all near-silent"
        return (f"{verdict}: {self.frames_in} inbound frames ({self.bytes_in} bytes) over "
                f"{secs:.0f}s, {self.loud_frames} with real signal.")


def _peak(pcm: bytes) -> int:
    peak = 0
    for i in range(0, len(pcm) - 1, 2):
        v = int.from_bytes(pcm[i:i + 2], "little", signed=True)
        peak = max(peak, abs(v))
    return peak


async def main():
    cfg = load_config()
    if not cfg.get("api_id") or not cfg.get("owner_id"):
        log.error("api_id and owner_id must be set in config.json")
        sys.exit(1)

    from telethon import TelegramClient
    client = TelegramClient(cfg["session_name"], cfg["api_id"], cfg["api_hash"])
    await client.start(phone=cfg["phone"])
    me = await client.get_me()
    log.info("signed in as %s (id=%s)", me.first_name, me.id)

    probe = EchoProbe()
    leg = TelegramCallLeg(client, cfg["owner_id"])
    probe.leg = leg
    leg.on_pcm = probe.on_pcm
    leg.on_connected = lambda: log.info(
        "call is up — SPEAK NOW, you should hear yourself back")
    leg.on_ended = lambda: log.info("call ended | %s", probe.report())
    leg.install(asyncio.get_running_loop())

    log.info("ready — call this account from user id %s and say something",
             cfg["owner_id"])
    log.info("frame geometry: %d bytes = 10ms @ 48kHz mono int16", FRAME_BYTES)
    try:
        await client.run_until_disconnected()
    finally:
        if leg.active:
            await leg.hangup()
        log.info("verdict | %s", probe.report())


if __name__ == "__main__":
    asyncio.run(main())
