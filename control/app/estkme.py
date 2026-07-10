"""
Helpers for ESTKme dual-SE detection (ATR + product AID SKU), matching sigmo's lpa/estkme.go.

Dual SE only for SKU "ESTKme Max" / "ESTKme Plus+":
  SE1 (se0) AID A06573746B6D65FFFF4953442D522030
  SE2 (se1) AID A06573746B6D65FFFF4953442D522031
Otherwise a single default eUICC (lpac auto-probes the GSMA ISD-R AID).
"""
from __future__ import annotations

import logging
from typing import Optional

from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.System import readers

log = logging.getLogger("vowifi.lpa.estkme")

ESTK_PRODUCT_AID = "A06573746B6D65FFFFFFFFFFFF6D6774"
ESTK_SE0_AID = "A06573746B6D65FFFF4953442D522030"
ESTK_SE1_AID = "A06573746B6D65FFFF4953442D522031"

# Historical bytes spelling "estk.me" — present on known ESTKme ATRs.
_ESTK_MARKER = bytes([0x65, 0x73, 0x74, 0x6B, 0x2E, 0x6D, 0x65])  # estk.me

ESTKME_ATRS = {
    bytes([0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x15,
           0x57, 0x65, 0x73, 0x74, 0x6B, 0x2E, 0x6D, 0x65, 0xC1]),
    bytes([0x3B, 0x9F, 0x96, 0x80, 0x3F, 0xC7, 0x82, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x15,
           0x57, 0x65, 0x73, 0x74, 0x6B, 0x2E, 0x6D, 0x65, 0x63]),
    bytes([0x3B, 0xBF, 0x93, 0x00, 0x80, 0x1F, 0xC6, 0x80, 0x31, 0xE0, 0x73, 0xFE, 0x21, 0x13,
           0x57, 0x65, 0x73, 0x74, 0x6B, 0x2E, 0x6D, 0x65, 0xE3]),
}

DEFAULT_SE = {"id": "default", "label": "eUICC", "aid": None}
DUAL_SES = (
    {"id": "se0", "label": "SE1", "aid": ESTK_SE0_AID},
    {"id": "se1", "label": "SE2", "aid": ESTK_SE1_AID},
)


def is_estkme_atr(atr: bytes) -> bool:
    """True for known ESTKme ATRs, or any ATR that embeds the 'estk.me' marker."""
    if not atr:
        return False
    if atr in ESTKME_ATRS:
        return True
    return _ESTK_MARKER in atr


def is_estkme_dual_sku(sku: str) -> bool:
    return (sku or "").strip() in ("ESTKme Max", "ESTKme Plus+")


def ses_for_sku(sku: str) -> list[dict] | None:
    if not is_estkme_dual_sku(sku):
        return None
    return [dict(s) for s in DUAL_SES]


def _hx(s: str) -> list[int]:
    s = s.replace(" ", "")
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]


def _set_cla(cla: int, channel: int) -> int:
    if channel < 4:
        return (cla & 0x9C) | channel
    if channel < 20:
        return (cla & 0xB0) | 0x40 | (channel - 4)
    return cla


def _find_reader(reader_name: str | None, reader_index: int = 0):
    rlist = readers()
    if reader_name:
        for r in rlist:
            if reader_name in str(r):
                return r
        raise RuntimeError(f"reader not found: {reader_name}")
    if reader_index < 0 or reader_index >= len(rlist):
        raise RuntimeError("reader index out of range")
    return rlist[reader_index]


def read_estk_sku(reader_name: str | None = None, reader_index: int = 0) -> Optional[str]:
    """Return ESTKme SKU string, or None if ATR/product AID/SKU read fails."""
    try:
        r = _find_reader(reader_name, reader_index)
    except Exception as e:  # noqa
        log.info("ESTKme reader resolve failed: %r", e)
        return None
    try:
        conn = r.createConnection()
        conn.connect()
    except (NoCardException, CardConnectionException) as e:
        log.info("ESTKme connect failed: %r", e)
        return None
    try:
        atr = bytes(conn.getATR() or [])
        atr_hex = atr.hex().upper()
        if not is_estkme_atr(atr):
            log.info("ESTKme ATR not matched reader=%s atr=%s (single eUICC path)",
                     reader_name or reader_index, atr_hex or "-")
            return None
        log.info("ESTKme ATR matched reader=%s atr=%s — reading SKU",
                 reader_name or reader_index, atr_hex)
        # MANAGE CHANNEL — open
        data, s1, s2 = conn.transmit([0x00, 0x70, 0x00, 0x00, 0x01])
        if (s1, s2) != (0x90, 0x00) or not data:
            log.info("ESTKme MANAGE CHANNEL open failed %02X%02X", s1, s2)
            return None
        ch = int(data[0])
        try:
            aid = _hx(ESTK_PRODUCT_AID)
            sel = [_set_cla(0x00, ch), 0xA4, 0x04, 0x00, len(aid)] + aid
            _d, s1, s2 = conn.transmit(sel)
            if s1 == 0x61:
                conn.transmit([_set_cla(0x00, ch), 0xC0, 0x00, 0x00, s2])
            elif (s1, s2) != (0x90, 0x00):
                log.info("ESTKme product SELECT failed %02X%02X", s1, s2)
                return None
            # INS=0x00 P1=0x03 — ESTKme product "read SKU string".
            # Some cards reject Le=0 with 6Cxx (correct length in SW2); retry with that Le.
            cmd = [_set_cla(0x00, ch), 0x00, 0x03, 0x00, 0x00]
            resp, s1, s2 = conn.transmit(cmd)
            if s1 == 0x6C:
                cmd = [_set_cla(0x00, ch), 0x00, 0x03, 0x00, s2]
                resp, s1, s2 = conn.transmit(cmd)
            elif s1 == 0x61:
                resp, s1, s2 = conn.transmit(
                    [_set_cla(0x00, ch), 0xC0, 0x00, 0x00, s2])
            if (s1, s2) != (0x90, 0x00):
                log.info("ESTKme SKU read failed %02X%02X", s1, s2)
                return None
            sku = bytes(resp or []).decode("utf-8", errors="replace").strip()
            log.info("ESTKme SKU reader=%s sku=%r", reader_name or reader_index, sku)
            return sku
        finally:
            try:
                conn.transmit([0x00, 0x70, 0x80, ch, 0x00])
            except Exception:  # noqa
                pass
    except Exception as e:  # noqa
        log.info("ESTKme SKU probe error: %r", e)
        return None
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa
            pass


def discover_ses(reader_name: str | None = None, reader_index: int = 0) -> list[dict]:
    """Return SE descriptors for this card (dual SE or single default)."""
    sku = read_estk_sku(reader_name, reader_index)
    if sku:
        dual = ses_for_sku(sku)
        if dual:
            log.info("ESTKme dual SE detected reader=%s sku=%r", reader_name or reader_index, sku)
            return dual
        log.info("ESTKme SKU is not dual-SE reader=%s sku=%r — single eUICC",
                 reader_name or reader_index, sku)
    return [dict(DEFAULT_SE)]


def resolve_se(ses: list[dict], se_id: str | None = None, aid: str | None = None) -> dict:
    """Pick an SE from a discovered list. Prefer explicit aid, then se_id."""
    if aid:
        aid_n = aid.strip().upper().replace(" ", "")
        for se in ses:
            if (se.get("aid") or "").upper() == aid_n:
                return dict(se)
        # Allow caller-supplied custom AID even if not in the discovered list.
        return {"id": se_id or "custom", "label": se_id or "eUICC", "aid": aid_n}
    if se_id:
        for se in ses:
            if se.get("id") == se_id:
                return dict(se)
        raise KeyError(f"eUICC SE not found: {se_id}")
    if len(ses) == 1:
        return dict(ses[0])
    raise KeyError("eUICC SE is required for dual-SE cards")
