#!/usr/bin/env python3
"""
pin_keeper.py - Keep the USIM CHV1 (PIN) verified for the whole engine lifetime.

Why: swu_ike's EAP-AKA (IKE) and Asterisk's ims_aka (SIP) both run AUTHENTICATE against
the USIM, which requires CHV1 verified. Empirically, PIN verification persists at the card
level across separate PC/SC connections as long as the card stays powered. So we verify
once, then hold an idle connection open and only re-verify when the card is re-inserted /
reset. We do NOT poll with SELECTs (that would race with swu_ike/ami_usim APDU sequences,
which pcscd does not serialize as groups).

Config via env (set by entrypoint from /config/instance.json):
  USIM_PIN        - the CHV1 PIN (digits). If empty/"none", PIN is assumed disabled.
  USIM_READER     - "imsi:<IMSI>" (preferred) or integer reader index. Default 0.
  VOWIFI_RUNDIR   - status dir (default /run/vowifi)

Writes JSON status to $VOWIFI_RUNDIR/pin_status.json:
  {"state": "...", "tries_left": N, "reader": "...", "ts": ...}
States: NO_READER, NO_CARD, PIN_DISABLED, VERIFIED, WRONG_PIN, PIN_BLOCKED, ERROR
Exit code is always 0 while running; it loops forever. A non-recoverable PIN problem
(WRONG_PIN / PIN_BLOCKED) is reported in status and the process keeps running so the
manager can surface it (it will retry on next card insert).
"""
import json
import os
import sys
import time

from smartcard.System import readers
from smartcard.util import toBytes, toHexString
from smartcard.Exceptions import NoCardException, CardConnectionException
from smartcard.scard import SCardBeginTransaction, SCardEndTransaction, SCARD_LEAVE_CARD


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


class _Tx:
    """Best-effort PC/SC transaction: exclusive card access for a short APDU sequence."""
    def __init__(self, conn):
        self.conn = conn
        self.hcard = None

    def __enter__(self):
        self.hcard = _hcard(self.conn)
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

RUNDIR = os.environ.get("VOWIFI_RUNDIR", "/run/vowifi")
STATUS_PATH = os.path.join(RUNDIR, "pin_status.json")
MIN_TRIES = 2  # never spend the PIN when only this many attempts remain (avoid PUK lock)


def log(msg):
    print(f"[pin_keeper] {msg}", flush=True)


def write_status(state, tries_left=None, reader=None, detail=None):
    os.makedirs(RUNDIR, exist_ok=True)
    data = {"state": state, "tries_left": tries_left, "reader": reader,
            "detail": detail, "ts": int(time.time())}
    tmp = STATUS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, STATUS_PATH)
    log(f"status={state} tries_left={tries_left} detail={detail}")


def swap_nibbles(s):
    return "".join([x + y for x, y in zip(s[1::2], s[0::2])])


def dec_imsi(ef_hex):
    l = int(ef_hex[0:2], 16) * 2 - 1
    swapped = swap_nibbles(ef_hex[2:]).rstrip("f")
    return swapped[1:]


# 3GPP USIM AID prefix. EF_DIR record 1 is NOT always the USIM (China Telecom cards
# list CSIM first), so scan the records and pick the USIM by AID.
USIM_AID_PREFIX = "A0000000871002"


def _usim_aid_from_dir(conn):
    """Scan EF_DIR records for the USIM AID; prefer 3GPP USIM, fall back to the first
    application. Returns (aid_len, aid_hex) or None."""
    d, s1, s2 = conn.transmit(toBytes("00a40004022f0000"))  # SELECT EF.DIR
    if s1 != 0x61:
        return None
    fcp, s1, s2 = conn.transmit(toBytes("00C00000") + [s2])
    if s1 != 0x90 or len(fcp) < 8:
        return None
    rec_len = fcp[7]
    first = None
    for rec in range(1, 11):
        d, s1, s2 = conn.transmit(toBytes("00b2") + [rec, 0x04, rec_len])
        # record template: 61 <len> 4F <aidlen> <AID...> [50 <len> label]
        if s1 != 0x90 or len(d) < 5 or d[0] != 0x61 or d[2] != 0x4F:
            break
        aid_len = d[3]
        aid = "".join("%02X" % b for b in d[4:4 + aid_len])
        if len(aid) < aid_len * 2:
            break
        if aid.startswith(USIM_AID_PREFIX):
            return aid_len, aid
        if first is None:
            first = (aid_len, aid)
    return first


def select_adf_usim(conn):
    """SELECT MF -> EF.DIR -> USIM AID -> ADF.USIM. Returns True on success."""
    conn.transmit(toBytes("00a40004023f0000"))          # SELECT MF
    got = _usim_aid_from_dir(conn)
    if not got:
        return False
    aid_len, aid = got
    d, s1, s2 = conn.transmit(toBytes("00a40404") + [aid_len] + toBytes(aid))
    return s1 == 0x61


def read_imsi(conn):
    conn.transmit(toBytes("00a40004026f0700"))
    d, s1, s2 = conn.transmit(toBytes("00b0000009"))
    if s1 != 0x90:
        return None
    return dec_imsi(bytes(d).hex())


def pin_tries_left(conn):
    """VERIFY with empty body -> 63Cx returns remaining tries without spending one."""
    d, s1, s2 = conn.transmit(toBytes("0020000100"))
    if s1 == 0x63:
        return s2 & 0x0F
    if (s1, s2) == (0x90, 0x00):
        return None  # PIN already verified / not required in this state
    if (s1, s2) == (0x69, 0x83):
        return 0     # blocked
    return None


def verify_pin(conn, pin):
    body = [ord(c) for c in pin] + [0xFF] * (8 - len(pin))
    d, s1, s2 = conn.transmit(toBytes("00200001") + [0x08] + body)
    return s1, s2


def read_iccid(conn):
    conn.transmit(toBytes("00a40004023f0000"))
    conn.transmit(toBytes("00a40004022fe200"))
    d, s1, s2 = conn.transmit(toBytes("00b000000a"))
    if s1 != 0x90:
        return None
    hx = bytes(d).hex()
    return swap_nibbles(hx).rstrip("f")


def find_reader(reader_spec):
    """Return (reader, open_connection) for the target SIM.

    Matching strategy that works with multiple readers (some empty) WITHOUT needing the
    PIN first:
      - imsi:<IMSI>  -> single reader: use it. Multiple readers: read ICCID (no PIN needed)
                        on each present card; if the target's ICCID was learned (see
                        USIM_ICCID env) match on it, otherwise fall back to trying IMSI
                        (works only once PIN is already satisfied) and finally the first
                        readable card.
      - iccid:<ICCID> -> match by ICCID (always readable, no PIN).
      - <index>      -> that reader index.
    """
    rlist = readers()
    if not rlist:
        return None, None

    def _open(r):
        try:
            c = r.createConnection()
            c.connect()
            return c
        except Exception:
            return None

    target_iccid = os.environ.get("USIM_ICCID", "").strip()

    if isinstance(reader_spec, str) and reader_spec.startswith("iccid:"):
        want = reader_spec[6:]
        for r in rlist:
            conn = _open(r)
            if conn is None:
                continue
            if read_iccid(conn) == want:
                return r, conn
            try: conn.disconnect()
            except Exception: pass
        return None, None

    if isinstance(reader_spec, str) and reader_spec.startswith("imsi:"):
        target = reader_spec[5:]
        if len(rlist) == 1:
            conn = _open(rlist[0])
            return (rlist[0], conn) if conn else (None, None)
        # Multiple readers: only consider readers that actually have a card (open succeeds),
        # then match by ICCID (no PIN), then by IMSI (if PIN already satisfied), then first.
        candidates = []
        for r in rlist:
            conn = _open(r)
            if conn is None:
                continue                      # empty reader -> skip
            candidates.append((r, conn))
        if not candidates:
            return None, None
        # 1) match by stored ICCID (always readable)
        if target_iccid:
            for r, conn in candidates:
                if read_iccid(conn) == target_iccid:
                    _close_others(candidates, conn)
                    return r, conn
        # 2) match by IMSI (only works if PIN already verified on the card)
        for r, conn in candidates:
            if select_adf_usim(conn) and read_imsi(conn) == target:
                _close_others(candidates, conn)
                return r, conn
        # 3) fall back to the first card-bearing reader
        r, conn = candidates[0]
        _close_others(candidates, conn)
        return r, conn

    try:
        idx = int(reader_spec)
    except (TypeError, ValueError):
        idx = 0
    if idx >= len(rlist):
        return None, None
    conn = _open(rlist[idx])
    return (rlist[idx], conn) if conn else (None, None)


def _close_others(candidates, keep):
    for _, c in candidates:
        if c is not keep:
            try: c.disconnect()
            except Exception: pass


def ensure_pin(reader_spec, pin):
    """Connect, verify PIN if enabled, return an open connection to HOLD (keeps the card
    powered so PIN stays verified). All card I/O happens inside a transaction."""
    r, conn = find_reader(reader_spec)
    if r is None:
        write_status("NO_CARD", reader=str(reader_spec))
        return None
    rname = str(r)
    try:
        with _Tx(conn):
            if not select_adf_usim(conn):
                write_status("NO_CARD", reader=rname, detail="ADF.USIM select failed")
                conn.disconnect()
                return None

            tries = pin_tries_left(conn)
            if not pin or pin.lower() in ("none", "disabled", ""):
                write_status("PIN_DISABLED", tries_left=tries, reader=rname)
                return conn
            if tries is None:
                # already verified in this card session (9000) -> nothing to do
                write_status("VERIFIED", tries_left=None, reader=rname)
                return conn
            if tries == 0:
                write_status("PIN_BLOCKED", tries_left=0, reader=rname)
                return conn
            if tries < MIN_TRIES:
                write_status("PIN_BLOCKED", tries_left=tries, reader=rname,
                             detail=f"refusing verify with only {tries} tries left (PUK risk)")
                return conn

            s1, s2 = verify_pin(conn, pin)
            if (s1, s2) == (0x90, 0x00):
                write_status("VERIFIED", tries_left=3, reader=rname)
                return conn
            if s1 == 0x63:
                write_status("WRONG_PIN", tries_left=s2 & 0x0F, reader=rname)
                return conn
            if (s1, s2) == (0x69, 0x83):
                write_status("PIN_BLOCKED", tries_left=0, reader=rname)
                return conn
            write_status("ERROR", reader=rname, detail=f"verify sw={s1:02x}{s2:02x}")
            return conn
    except Exception as e:  # noqa
        write_status("ERROR", reader=rname, detail=repr(e))
        try:
            conn.disconnect()
        except Exception:
            pass
        return None


def main():
    pin = os.environ.get("USIM_PIN", "")
    reader_spec = os.environ.get("USIM_READER", "0")
    log(f"starting; reader={reader_spec} pin={'set' if pin else 'none'}")

    # Verify PIN once, then HOLD the connection open indefinitely. An open handle keeps
    # the card powered, so CHV1 verification persists for swu_ike (IKE EAP-AKA) and
    # ami_usim (SIP IMS-AKA). We do NOT poll the card (polling races with their APDU
    # sequences); we only re-acquire if the held connection genuinely dies.
    conn = None
    idle_ticks = 0
    while True:
        try:
            if conn is None:
                conn = ensure_pin(reader_spec, pin)
                if conn is None:
                    time.sleep(3)
                    continue
                idle_ticks = 0
            time.sleep(5)
            idle_ticks += 1
            # Rare, cheap liveness probe via a SEPARATE short-lived shared connection so we
            # never disturb the held connection's selected file / PIN state. Every ~60s.
            if idle_ticks >= 12:
                idle_ticks = 0
                if not _card_present(reader_spec):
                    log("card removed; will re-verify on re-insert")
                    try:
                        conn.disconnect()
                    except Exception:
                        pass
                    conn = None
                    write_status("NO_CARD", reader=str(reader_spec))
        except KeyboardInterrupt:
            break
        except Exception as e:  # noqa
            log(f"exception: {e!r}")
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass
            conn = None
            write_status("ERROR", reader=str(reader_spec), detail=repr(e))
            time.sleep(3)


def _card_present(reader_spec):
    """Presence check that does not touch the held connection: list readers only."""
    try:
        rlist = readers()
        return len(rlist) > 0
    except Exception:
        return False


if __name__ == "__main__":
    main()
