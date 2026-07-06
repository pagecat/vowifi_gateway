"""
card.py - Non-intrusive reader/card presence detection for the manager.

Uses SCardGetStatusChange (reader state only, no APDUs / no card connect), so it can run
continuously alongside the engine's card access without disturbing it. Returns presence
per reader index aligned with smartcard.System.readers() (what sim.read_card uses).
"""
from __future__ import annotations

import logging
import time

from smartcard.scard import (
    SCardEstablishContext, SCardReleaseContext, SCardListReaders, SCardGetStatusChange,
    SCARD_SCOPE_USER, SCARD_STATE_UNAWARE, SCARD_STATE_PRESENT, SCARD_STATE_EMPTY,
    SCARD_STATE_CHANGED, SCARD_S_SUCCESS, SCARD_E_TIMEOUT, SCARD_E_NO_READERS_AVAILABLE,
)

log = logging.getLogger("vowifi.card")

# pcscd's hotplug pseudo-reader: including it in SCardGetStatusChange makes the call
# return as soon as the READER LIST changes (reader plugged/unplugged), not only when a
# card moves inside a known reader. Supported by pcsc-lite >= 1.4.
PNP_NOTIFICATION = "\\\\?PnP?\\Notification"


def reader_states() -> list[dict] | None:
    """[{index, name, present}] for each reader, index matching readers().
    Returns [] ONLY when pcscd authoritatively reports zero readers; returns None on
    transient PC/SC errors (pcscd down/restarting) so the caller can skip that cycle
    instead of treating an outage as "every reader was unplugged" and killing engines."""
    hresult, hctx = SCardEstablishContext(SCARD_SCOPE_USER)
    if hresult != SCARD_S_SUCCESS:
        return None
    try:
        hresult, names = SCardListReaders(hctx, [])
        if hresult == SCARD_E_NO_READERS_AVAILABLE or (hresult == SCARD_S_SUCCESS and not names):
            return []
        if hresult != SCARD_S_SUCCESS:
            return None
        rs = [(n, SCARD_STATE_UNAWARE) for n in names]
        hresult, new = SCardGetStatusChange(hctx, 0, rs)
        if hresult != SCARD_S_SUCCESS:
            return None
        out = []
        for i, (name, event, atr) in enumerate(new):
            present = bool(event & SCARD_STATE_PRESENT) and not bool(event & SCARD_STATE_EMPTY)
            out.append({"index": i, "name": name, "present": present})
        return out
    finally:
        SCardReleaseContext(hctx)


def wait_for_change(timeout_s: float = 5.0) -> bool:
    """Block until a reader is plugged/unplugged or a card is inserted/removed, or until
    timeout_s. Event-driven: SCardGetStatusChange on the current readers plus the PnP
    notification pseudo-reader, so hotplug wakes the caller instantly instead of on the
    next poll. Any PC/SC error (pcscd down, no readers, old pcsc-lite) degrades to a
    plain sleep so the caller's scan loop keeps working. Returns True when something
    (probably) changed, False on a clean timeout."""
    fallback = min(timeout_s, 1.2)
    hctx = None
    try:
        hresult, hctx = SCardEstablishContext(SCARD_SCOPE_USER)
        if hresult != SCARD_S_SUCCESS:
            hctx = None
            time.sleep(fallback)
            return True
        hresult, names = SCardListReaders(hctx, [])
        if hresult != SCARD_S_SUCCESS:
            names = []
        rs = [(n, SCARD_STATE_UNAWARE) for n in [*names, PNP_NOTIFICATION]]
        # First call resolves UNAWARE into the actual current state. With zero real
        # readers pcsc-lite reports nothing CHANGED for the PnP pseudo-reader and the
        # 0-timeout call returns SCARD_E_TIMEOUT — the returned states are still the
        # resolved snapshot, so both codes proceed to the blocking wait.
        hresult, cur = SCardGetStatusChange(hctx, 0, rs)
        if hresult not in (SCARD_S_SUCCESS, SCARD_E_TIMEOUT):
            time.sleep(fallback)
            return True
        # ...second call blocks until any state differs from that snapshot.
        rs = [(name, evt & ~SCARD_STATE_CHANGED) for name, evt, _atr in cur]
        hresult, _ = SCardGetStatusChange(hctx, int(timeout_s * 1000), rs)
        return hresult == SCARD_S_SUCCESS
    except Exception as e:  # noqa
        log.debug("wait_for_change error: %r", e)
        time.sleep(fallback)
        return True
    finally:
        if hctx is not None:
            SCardReleaseContext(hctx)
