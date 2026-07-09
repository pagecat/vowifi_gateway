"""
usbreader.py - Map live PC/SC reader indices to their STABLE physical USB port path.

Why this exists
---------------
The rig can hold two *identical* smart-card readers (e.g. Alcor/AK9563 2ce3:9563) that carry
**no USB serial number**. pcscd/libccid can only tell such readers apart by USB *enumeration
order*, which races at boot / pcscd restart / power-up timing. So the reader NAME suffix
("00 00" / "01 00") and therefore the smartcard.System.readers() index are NOT stable — they can
flip between two physically-untouched readers. A line bound to "reader index 1" then silently
authenticates against the wrong (or an empty) reader -> the engine reads no card -> swu_ike falls
back to DEFAULT RES/CK/IK -> the carrier rejects EAP-AKA.

The fix is to bind a line to the reader's physical USB **port path** (e.g. "3-2" = bus 3, port 2),
which only changes if the reader is physically moved to another socket. This module resolves the
current index<->port mapping so callers can (a) capture a line's port at provision time and
(b) re-resolve the live index for that port at every start.

How the mapping is derived (verified on the Pi, host AND inside the engine container):
    live index --SCARD_ATTR_CHANNEL_ID--> (bus, devnum) --/sys/bus/usb/devices/*/{busnum,devnum}--> port
      idx0  CHANNEL_ID 05012000  bus1 dev5  -> "1-2"
      idx1  CHANNEL_ID 02032000  bus3 dev2  -> "3-2"
CHANNEL_ID for a USB reader is a little-endian u32 = 0x00200000 | (bus<<8) | devnum. The devnum
changes on re-enumeration, but it is only used transiently here to map an already-open handle back
to its sysfs node; the resulting port path (the sysfs dir basename) is the stable identity we keep.

Everything is best-effort: any reader that can't be resolved (no CHANNEL_ID, sysfs unavailable) is
simply omitted, so callers fall back to their existing index/ICCID logic and are never worse off.
"""
from __future__ import annotations

import glob
import logging
import os

from smartcard.System import readers

try:
    from smartcard.scard import (
        SCardEstablishContext, SCardConnect, SCardGetAttrib, SCardDisconnect,
        SCARD_SCOPE_USER, SCARD_SHARE_DIRECT, SCARD_LEAVE_CARD,
        SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_ATTR_CHANNEL_ID, SCARD_S_SUCCESS,
    )
    _SCARD_OK = True
except Exception:  # noqa - pyscard without the low-level scard bindings
    _SCARD_OK = False

log = logging.getLogger("vowifi.usbreader")

_SYS_USB = "/sys/bus/usb/devices"


def _channel_id_bus_dev(reader_name: str):
    """(bus, devnum) for a reader via SCARD_ATTR_CHANNEL_ID, or None. Uses a SHARE_DIRECT
    connection: no card is required and no APDU is sent, so this does NOT disturb a card an
    engine is actively using."""
    if not _SCARD_OK:
        return None
    hctx = hcard = None
    try:
        hr, hctx = SCardEstablishContext(SCARD_SCOPE_USER)
        if hr != SCARD_S_SUCCESS:
            return None
        hr, hcard, _proto = SCardConnect(hctx, reader_name, SCARD_SHARE_DIRECT,
                                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
        if hr != SCARD_S_SUCCESS:
            return None
        hr, val = SCardGetAttrib(hcard, SCARD_ATTR_CHANNEL_ID)
        if hr != SCARD_S_SUCCESS or not val or len(val) < 4:
            return None
        v = val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] << 24)
        # 0x0020xxxx marks a USB transport; low 16 bits = (bus<<8)|devnum.
        if (v >> 16) != 0x0020:
            return None
        return (v >> 8) & 0xff, v & 0xff
    except Exception as e:  # noqa
        log.debug("channel_id read failed for %s: %r", reader_name, e)
        return None
    finally:
        if hcard is not None:
            try:
                SCardDisconnect(hcard, SCARD_LEAVE_CARD)
            except Exception:
                pass


def _port_path_for(bus: int, devnum: int):
    """sysfs USB port path (dir basename, e.g. '3-2') for a (busnum, devnum), or None."""
    try:
        entries = glob.glob(_SYS_USB + "/*/")
    except Exception:
        return None
    for d in entries:
        try:
            with open(os.path.join(d, "busnum")) as f:
                b = int(f.read())
            with open(os.path.join(d, "devnum")) as f:
                n = int(f.read())
        except Exception:
            continue
        if b == bus and n == devnum:
            return os.path.basename(d.rstrip("/"))
    return None


def reader_port_paths() -> dict[int, str]:
    """{live_reader_index: usb_port_path} for every reader we can resolve. Readers whose port
    can't be determined are omitted (never guessed)."""
    out: dict[int, str] = {}
    try:
        rlist = readers()
    except Exception as e:  # noqa
        log.debug("readers() failed: %r", e)
        return out
    for i, r in enumerate(rlist):
        bd = _channel_id_bus_dev(str(r))
        if not bd:
            continue
        port = _port_path_for(bd[0], bd[1])
        if port:
            out[i] = port
    return out


def port_for_index(index: int) -> str | None:
    """USB port path currently at this reader index, or None."""
    return reader_port_paths().get(int(index))


def index_for_port(port: str) -> int | None:
    """Live reader index currently holding this USB port path, or None if that port is not
    present. This is the resolution that makes a line stick to its physical reader regardless
    of how pcscd enumerated the (identical) readers this time."""
    if not port:
        return None
    for idx, p in reader_port_paths().items():
        if p == port:
            return idx
    return None
