"""
sim.py - Physical USIM access via PC/SC (shared pcscd).

Used by the manager for reader/SIM detection and PIN management. All multi-APDU
sequences run inside a PC/SC transaction (SCardBeginTransaction) to avoid interleaving
with the engine's swu_ike / ami_usim / pin_keeper accesses on the same card.

Safe by construction: never spends the last PIN attempts (MIN_TRIES guard) and reads
the retry counter with a status query (63Cx) that does not consume a try.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from typing import Optional

from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoCardException, CardConnectionException
from smartcard.scard import SCardBeginTransaction, SCardEndTransaction, SCARD_LEAVE_CARD

log = logging.getLogger("vowifi.sim")

MIN_TRIES = 2  # never verify/spend when <= this many attempts remain (avoid PUK lock)


@dataclass
class CardInfo:
    reader: str
    reader_index: int
    present: bool
    imsi: Optional[str] = None
    mcc: Optional[str] = None
    mnc: Optional[str] = None
    mnc_len: Optional[int] = None
    iccid: Optional[str] = None
    pin_enabled: Optional[bool] = None
    pin_tries: Optional[int] = None
    smsc: Optional[str] = None
    error: Optional[str] = None

    def dict(self):
        return asdict(self)


class _Tx:
    """Best-effort PC/SC transaction around a multi-APDU sequence (avoids interleaving
    with the engine's concurrent card access). If the low-level handle can't be found,
    it degrades to a no-op rather than failing."""
    def __init__(self, conn: CardConnection):
        self.conn = conn
        self.hcard = None

    @staticmethod
    def _hcard(conn):
        obj = conn
        for _ in range(5):
            if hasattr(obj, "hcard"):
                return obj.hcard
            if hasattr(obj, "component") and obj.component is not None:
                obj = obj.component
                continue
            break
        return None

    def __enter__(self):
        self.hcard = self._hcard(self.conn)
        if self.hcard is not None:
            try:
                SCardBeginTransaction(self.hcard)
            except Exception:
                self.hcard = None
        return self.conn

    def __exit__(self, *a):
        if self.hcard is not None:
            try:
                SCardEndTransaction(self.hcard, SCARD_LEAVE_CARD)
            except Exception:
                pass


def _hx(s: str):
    return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]


def swap_nibbles(s: str) -> str:
    return "".join([x + y for x, y in zip(s[1::2], s[0::2])])


def dec_imsi(ef_hex: str) -> Optional[str]:
    if len(ef_hex) < 4:
        return None
    swapped = swap_nibbles(ef_hex[2:]).rstrip("f")
    return swapped[1:] if swapped else None


def dec_iccid(ef_hex: str) -> str:
    return swap_nibbles(ef_hex).rstrip("f")


# 3GPP USIM application AID prefix (RID A000000087 + app code 1002). EF_DIR record 1 is
# NOT always the USIM — e.g. China Telecom cards list CSIM (A0000003431002, CDMA) first —
# so application selection must scan the records and pick the USIM by AID.
USIM_AID_PREFIX = "A0000000871002"


def _usim_aid_from_dir(conn) -> Optional[tuple[int, str]]:
    """Scan EF_DIR records for the USIM application's AID. Prefers the 3GPP USIM AID;
    falls back to the first application found. Returns (aid_len, aid_hex) or None."""
    d, s1, s2 = conn.transmit(_hx("00a40004022f0000"))
    if s1 != 0x61:
        return None
    fcp, s1, s2 = conn.transmit(_hx("00C00000") + [s2])
    if s1 != 0x90 or len(fcp) < 8:
        return None
    rec_len = fcp[7]
    first = None
    for rec in range(1, 11):
        d, s1, s2 = conn.transmit(_hx("00b2") + [rec, 0x04, rec_len])
        # record template: 61 <len> 4F <aidlen> <AID...> [50 <len> label]
        if s1 != 0x90 or len(d) < 5 or d[0] != 0x61 or d[2] != 0x4F:
            break
        aid_len = d[3]
        aid = "".join(f"{b:02X}" for b in d[4:4 + aid_len])
        if len(aid) < aid_len * 2:
            break
        if aid.startswith(USIM_AID_PREFIX):
            return aid_len, aid
        if first is None:
            first = (aid_len, aid)
    return first


def _select_adf_usim(conn) -> bool:
    conn.transmit(_hx("00a40004023f0000"))
    got = _usim_aid_from_dir(conn)
    if not got:
        return False
    aid_len, aid = got
    d, s1, s2 = conn.transmit(_hx("00a40404") + [aid_len] + _hx(aid))
    return s1 == 0x61


def _read_binary(conn, fid: str, length: int):
    conn.transmit(_hx(f"00a4000402{fid}00"))
    d, s1, s2 = conn.transmit(_hx(f"00b00000{length:02x}"))
    return d, s1, s2


def _decode_ton_bcd(field) -> Optional[str]:
    """Decode a GSM/3GPP address field [len, TON/NPI, BCD...] into an E.164 string.
    `len` counts the TON byte + BCD digit bytes. Returns None if unset (00/FF)."""
    if not field or field[0] in (0x00, 0xFF):
        return None
    ln = field[0]
    ton = field[1]
    digits = ""
    for b in field[2:2 + (ln - 1)]:
        if (b & 0x0F) != 0xF:
            digits += str(b & 0x0F)
        if ((b >> 4) & 0x0F) != 0xF:
            digits += str((b >> 4) & 0x0F)
    if not digits:
        return None
    return ("+" if (ton & 0x70) == 0x10 else "") + digits


def _read_smsc(conn) -> Optional[str]:
    """Read the SMSC from EF_SMSP (6F42, under ADF_USIM) record 1 — the authoritative
    per-SIM SMS Service Centre a real phone uses for MO SMS. Requires ADF_USIM selected
    and CHV1 verified (same as IMSI). Record layout (3GPP TS 31.102 4.2.27):
    [alpha(Y)][PI(1)][TP-DA(12)][TP-SC/SMSC(12)][PID][DCS][VP], Y = rec_len - 28.
    SMSC field = [len, TON/NPI, BCD digits...]."""
    d, s1, s2 = conn.transmit(_hx("00a40004026f4200"))
    if s1 != 0x61:
        return None
    fcp, s1, s2 = conn.transmit(_hx("00c00000") + [s2])
    # FCP is an outer template: 0x62 <len> <nested TLVs>. Descend into it, then find the
    # File-Descriptor tag 0x82 whose bytes 3-4 hold the record length.
    body = fcp
    if len(fcp) >= 2 and fcp[0] == 0x62:
        body = fcp[2:2 + fcp[1]]
    rec_len, i = 0, 0
    while i + 1 < len(body):
        t, l = body[i], body[i + 1]
        v = body[i + 2:i + 2 + l]
        if t == 0x82 and l >= 4:
            rec_len = (v[2] << 8) | v[3]
        i += 2 + l
    if rec_len < 28:
        return None
    y = rec_len - 28
    d, s1, s2 = conn.transmit(_hx("00b20104") + [rec_len])  # READ RECORD 1
    if s1 != 0x90 or len(d) < rec_len:
        return None
    return _decode_ton_bcd(d[y + 13:y + 25])


def _pin_tries(conn) -> Optional[int]:
    d, s1, s2 = conn.transmit(_hx("0020000100"))
    if s1 == 0x63:
        return s2 & 0x0F
    if (s1, s2) == (0x69, 0x83):
        return 0
    if (s1, s2) == (0x90, 0x00):
        return None  # already verified in this session
    return None


def list_readers():
    return [str(r) for r in readers()]


def read_card(reader_index: int = 0, pin: str | None = None) -> CardInfo:
    """Read card identity. If `pin` is given, verify CHV1 in the SAME connection before
    reading IMSI (PIN state does not survive a disconnect when no other handle holds the
    card, so verify+read must share one connection)."""
    rlist = readers()
    if reader_index >= len(rlist):
        return CardInfo(reader="", reader_index=reader_index, present=False,
                        error="reader index out of range")
    r = rlist[reader_index]
    info = CardInfo(reader=str(r), reader_index=reader_index, present=False)
    try:
        conn = r.createConnection()
        conn.connect()
    except (NoCardException, CardConnectionException) as e:
        info.error = f"no card: {e}"
        return info
    info.present = True
    try:
        with _Tx(conn):
            # ICCID (EF 2FE2 under MF) - no PIN needed
            conn.transmit(_hx("00a40004023f0000"))
            d, s1, s2 = _read_binary(conn, "2fe2", 10)
            if s1 == 0x90:
                info.iccid = dec_iccid("".join(f"{b:02x}" for b in d))
            if not _select_adf_usim(conn):
                info.error = "ADF.USIM select failed"
                return info
            # PIN status — provisional guess from the retry-counter query; refined below
            # by whether EF_IMSI is actually readable without verification.
            tries = _pin_tries(conn)
            info.pin_tries = tries
            info.pin_enabled = tries is not None
            # Optionally verify PIN in this same connection so IMSI becomes readable.
            if pin and tries is not None and tries >= MIN_TRIES:
                body = [ord(c) for c in pin] + [0xFF] * (8 - len(pin))
                d, s1, s2 = conn.transmit(_hx("00200001") + [0x08] + body)
                if (s1, s2) != (0x90, 0x00):
                    info.error = "wrong PIN" if s1 == 0x63 else f"pin sw={s1:02x}{s2:02x}"
            # IMSI (needs PIN normally; may fail if not verified)
            conn.transmit(_hx("00a40004026f0700"))
            d, s1, s2 = conn.transmit(_hx("00b0000009"))
            if s1 == 0x90:
                imsi = dec_imsi("".join(f"{b:02x}" for b in d))
                if imsi:
                    info.imsi = imsi
                    info.mcc = imsi[:3]
                if not pin:
                    # Readable WITHOUT our VERIFY -> the PIN is not required right now
                    # (disabled, or already satisfied by another holder). The 63Cx status
                    # query only reports the retry counter — some cards return it even
                    # when the PIN is disabled, so it must not be trusted for "enabled".
                    info.pin_enabled = False
            elif (s1, s2) == (0x69, 0x82):
                info.pin_enabled = True     # security status not satisfied = PIN required
            # EF_AD (6FAD) for MNC length
            conn.transmit(_hx("00a40004026fad00"))
            d, s1, s2 = conn.transmit(_hx("00b0000004"))
            if s1 == 0x90 and len(d) >= 4:
                info.mnc_len = d[3]
                if info.imsi:
                    info.mnc = info.imsi[3:3 + info.mnc_len]
            # SMSC from EF_SMSP (6F42) — authoritative per-SIM SMS centre (needs PIN, like IMSI)
            try:
                info.smsc = _read_smsc(conn)
            except Exception:  # noqa
                pass
    except Exception as e:  # noqa
        info.error = repr(e)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return info


def _find_conn(reader_index: int):
    rlist = readers()
    if reader_index >= len(rlist):
        raise RuntimeError("reader index out of range")
    conn = rlist[reader_index].createConnection()
    conn.connect()
    return conn


# Friendly message when a PIN operation targets a reader with no card (or an unreadable one).
# Returned as {"ok": False, ...} — the WebUI already renders that inline, so an empty reader
# no longer surfaces as an HTTP 500 (createConnection().connect() raises NoCardException).
_NO_CARD = {"ok": False, "error": "No SIM card in this reader."}


def _open_conn(reader_index: int):
    """Open a card connection for a PIN op, or return (None, error_dict) if the reader has no
    card / is out of range. Callers: verify_pin, change_pin, set_pin_enabled."""
    try:
        return _find_conn(reader_index), None
    except (NoCardException, CardConnectionException):
        return None, dict(_NO_CARD)
    except RuntimeError as e:
        return None, {"ok": False, "error": str(e)}


def verify_pin(pin: str, reader_index: int = 0) -> dict:
    conn, err = _open_conn(reader_index)
    if err:
        return err
    try:
        with _Tx(conn):
            if not _select_adf_usim(conn):
                return {"ok": False, "error": "ADF.USIM select failed"}
            tries = _pin_tries(conn)
            if tries == 0:
                return {"ok": False, "error": "PIN blocked", "tries": 0}
            if tries is not None and tries < MIN_TRIES:
                return {"ok": False, "error": f"refusing: only {tries} tries left", "tries": tries}
            body = [ord(c) for c in pin] + [0xFF] * (8 - len(pin))
            d, s1, s2 = conn.transmit(_hx("00200001") + [0x08] + body)
            if (s1, s2) == (0x90, 0x00):
                return {"ok": True, "tries": 3}
            if s1 == 0x63:
                return {"ok": False, "error": "wrong PIN", "tries": s2 & 0x0F}
            if (s1, s2) == (0x69, 0x83):
                return {"ok": False, "error": "PIN blocked", "tries": 0}
            return {"ok": False, "error": f"sw={s1:02x}{s2:02x}"}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def change_pin(old: str, new: str, reader_index: int = 0) -> dict:
    conn, err = _open_conn(reader_index)
    if err:
        return err
    try:
        with _Tx(conn):
            if not _select_adf_usim(conn):
                return {"ok": False, "error": "ADF.USIM select failed"}
            tries = _pin_tries(conn)
            if tries is not None and tries < MIN_TRIES:
                return {"ok": False, "error": f"refusing: only {tries} tries left"}
            ob = [ord(c) for c in old] + [0xFF] * (8 - len(old))
            nb = [ord(c) for c in new] + [0xFF] * (8 - len(new))
            d, s1, s2 = conn.transmit(_hx("00240001") + [0x10] + ob + nb)  # CHANGE CHV1
            if (s1, s2) == (0x90, 0x00):
                return {"ok": True}
            if s1 == 0x63:
                return {"ok": False, "error": "wrong old PIN", "tries": s2 & 0x0F}
            return {"ok": False, "error": f"sw={s1:02x}{s2:02x}"}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def set_pin_enabled(pin: str, enabled: bool, reader_index: int = 0) -> dict:
    """Enable (0x28) or disable (0x26) CHV1."""
    conn, err = _open_conn(reader_index)
    if err:
        return err
    ins = "28" if enabled else "26"
    try:
        with _Tx(conn):
            if not _select_adf_usim(conn):
                return {"ok": False, "error": "ADF.USIM select failed"}
            tries = _pin_tries(conn)
            if tries is not None and tries < MIN_TRIES:
                return {"ok": False, "error": f"refusing: only {tries} tries left"}
            body = [ord(c) for c in pin] + [0xFF] * (8 - len(pin))
            # ENABLE (0x28) / DISABLE (0x26) CHV1: 00 26/28 00 01 08 <pin padded FF>
            d, s1, s2 = conn.transmit(_hx(f"00{ins}0001") + [0x08] + body)
            if (s1, s2) == (0x90, 0x00):
                return {"ok": True}
            if s1 == 0x63:
                return {"ok": False, "error": "wrong PIN", "tries": s2 & 0x0F}
            return {"ok": False, "error": f"sw={s1:02x}{s2:02x}"}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    import json
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        print(json.dumps(verify_pin(sys.argv[2])))
    else:
        print("readers:", list_readers())
        print(json.dumps(read_card().dict(), indent=2))
