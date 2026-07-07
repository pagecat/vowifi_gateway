#!/usr/bin/env python3
"""
ami_usim.py - Bridge Asterisk (ims_aka) SIP authentication to the physical USIM via PC/SC.

Derived from phcoder/asterisk-docker (jolly). Changes:
  - VERIFY CHV1 (PIN) after selecting ADF.USIM, before AUTHENTICATE (reference didn't).
  - Clean type-annotation bug from the original (undefined Hexstr/Optional names).
  - Emit status/heartbeat JSON to $VOWIFI_RUNDIR/usim_status.json for the manager FSM.

On Asterisk 'AuthRequest' it runs USIM AUTHENTICATE and returns RES/CK/IK (or AUTS on
sync failure). Triggers registration on FullyBooted and confirms dedicated bearers.
"""
import asyncio
import configparser
import json
import os
import sys
import time

from panoramisk import Manager
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.scard import SCardBeginTransaction, SCardEndTransaction, SCARD_LEAVE_CARD

RUNDIR = os.environ.get("VOWIFI_RUNDIR", "/run/vowifi")
USIM_PIN = os.environ.get("USIM_PIN", "")


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
    """Best-effort PC/SC transaction: exclusive card access for the auth sequence, so it
    cannot interleave with pin_keeper / swu_ike APDUs on the shared card."""
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


def write_status(**kw):
    os.makedirs(RUNDIR, exist_ok=True)
    kw["ts"] = int(time.time())
    tmp = os.path.join(RUNDIR, "usim_status.json.tmp")
    with open(tmp, "w") as f:
        json.dump(kw, f)
    os.replace(tmp, os.path.join(RUNDIR, "usim_status.json"))


def swap_nibbles(s):
    return "".join([x + y for x, y in zip(s[1::2], s[0::2])])


def dec_imsi(ef):
    if len(ef) < 4:
        return None
    l = int(ef[0:2], 16) * 2 - 1
    swapped = swap_nibbles(ef[2:]).rstrip("f")
    if len(swapped) < 1:
        return None
    return swapped[1:]


# 3GPP USIM AID prefix. EF_DIR record 1 is NOT always the USIM (China Telecom cards
# list CSIM first), so scan the records and pick the USIM by AID.
USIM_AID_PREFIX = "A0000000871002"


def _usim_aid_from_dir(connection):
    """Scan EF_DIR records for the USIM AID; prefer 3GPP USIM, fall back to the first
    application. EF.DIR must be selectable from the current DF. Returns (len, hex) or None."""
    data, sw1, sw2 = connection.transmit(toBytes("00a40004022f0000"))  # SELECT EF.DIR
    if sw1 != 0x61:
        return None
    fcp, sw1, sw2 = connection.transmit(toBytes("00C00000") + [sw2])
    if sw1 != 0x90 or len(fcp) < 8:
        return None
    record_length = fcp[7]
    first = None
    for rec in range(1, 11):
        data, sw1, sw2 = connection.transmit(toBytes("00b2") + [rec, 0x04, record_length])
        if sw1 != 0x90 or len(data) < 5 or data[0] != 0x61 or data[2] != 0x4F:
            break
        aid_length = data[3]
        aid = "".join("%02X" % b for b in data[4:4 + aid_length])
        if len(aid) < aid_length * 2:
            break
        if aid.startswith(USIM_AID_PREFIX):
            return aid_length, aid
        if first is None:
            first = (aid_length, aid)
    return first


def make_connection_index(reader_index):
    r = readers()
    if reader_index >= len(r):
        return None
    connection = r[reader_index].createConnection()
    connection.connect()
    connection.transmit(toBytes("00a40004023f0000"))
    got = _usim_aid_from_dir(connection)
    if got is None:
        print("Failed to find USIM AID in EF.DIR")
        return None
    aid_length, aid = got
    print(f"Using aid={aid}")
    data, sw1, sw2 = connection.transmit(toBytes("00a40404") + [aid_length] + toBytes(aid))
    if sw1 != 0x61:
        print("Failed to select AID")
        return None
    return connection


def make_connection_name(reader_name):
    if isinstance(reader_name, str) and reader_name.startswith("imsi:"):
        target_imsi = reader_name[5:]
        for idx in range(len(readers())):
            connection = make_connection_index(idx)
            if connection is None:
                continue
            data, sw1, sw2 = connection.transmit(toBytes("00a40004026f0700"))
            if sw1 != 0x61:
                continue
            data, sw1, sw2 = connection.transmit(toBytes("00b0000009"))
            if (sw1, sw2) != (0x90, 0x00):
                continue
            imsi = dec_imsi(bytes(data).hex())
            print(f"Found IMSI {imsi}")
            if imsi == target_imsi:
                print(f"Found target imsi on reader {idx}")
                # re-select ADF.USIM after reading IMSI (IMSI read left EF selected)
                make_reselect_adf(connection)
                return connection
        print(f"IMSI {target_imsi} not found")
        return None
    return make_connection_index(int(reader_name))


def make_reselect_adf(connection):
    connection.transmit(toBytes("00a40004023f0000"))
    got = _usim_aid_from_dir(connection)
    if got is None:
        return
    aid_length, aid = got
    connection.transmit(toBytes("00a40404") + [aid_length] + toBytes(aid))


def select_adf_usim(connection):
    """SELECT MF -> EF.DIR -> USIM AID -> ADF.USIM. Returns True on success."""
    connection.transmit(toBytes("00a40004023f0000"))
    got = _usim_aid_from_dir(connection)
    if got is None:
        return False
    aid_length, aid = got
    data, sw1, sw2 = connection.transmit(toBytes("00a40404") + [aid_length] + toBytes(aid))
    return sw1 == 0x61


def open_usim(reader_spec):
    """Return an open connection positioned at ADF.USIM. For a single reader we use it
    directly (IMSI can't be read before PIN). For imsi:<IMSI> with multiple readers we
    verify PIN then match IMSI. Selection/verify happen under a transaction by the caller."""
    rlist = readers()
    if not rlist:
        return None
    if isinstance(reader_spec, str) and reader_spec.startswith("imsi:") and len(rlist) > 1:
        target = reader_spec[5:]
        for r in rlist:
            try:
                conn = r.createConnection()
                conn.connect()
            except Exception:
                continue
            with _Tx(conn):
                if select_adf_usim(conn) and verify_pin(conn):
                    conn.transmit(toBytes("00a40004026f0700"))
                    d, s1, s2 = conn.transmit(toBytes("00b0000009"))
                    if s1 == 0x90 and dec_imsi(bytes(d).hex()) == target:
                        return conn
            try:
                conn.disconnect()
            except Exception:
                pass
        return None
    # single reader, or explicit index
    idx = 0
    if isinstance(reader_spec, str) and reader_spec.isdigit():
        idx = int(reader_spec)
    if idx >= len(rlist):
        idx = 0
    conn = rlist[idx].createConnection()
    conn.connect()
    return conn


def verify_pin(connection):
    """Verify CHV1 if a PIN is configured. Idempotent: skips if already verified (9000)."""
    if not USIM_PIN or USIM_PIN.lower() in ("none", "disabled", ""):
        return True
    d, s1, s2 = connection.transmit(toBytes("0020000100"))
    if (s1, s2) == (0x90, 0x00):
        return True  # already verified in this card session
    if s1 == 0x63 and (s2 & 0x0F) < 2:
        print(f"Refusing PIN verify: only {s2 & 0x0F} tries left", flush=True)
        return False
    body = [ord(c) for c in USIM_PIN] + [0xFF] * (8 - len(USIM_PIN))
    d, s1, s2 = connection.transmit(toBytes("00200001") + [0x08] + body)
    if (s1, s2) == (0x90, 0x00):
        return True
    print(f"PIN verify failed sw={s1:02x}{s2:02x}", flush=True)
    return False


def read_res_ck_ik(reader_spec, rand, autn):
    res = ck = ik = auts = None
    conn = open_usim(reader_spec)
    if conn is None:
        write_status(state="NO_CARD")
        return res, ck, ik, auts
    try:
        with _Tx(conn):
            if not select_adf_usim(conn):
                write_status(state="NO_CARD", detail="ADF.USIM select failed")
                return res, ck, ik, auts
            if not verify_pin(conn):
                write_status(state="PIN_FAIL")
                return res, ck, ik, auts
            data, sw1, sw2 = conn.transmit(
                toBytes("008800812210" + rand.upper() + "10" + autn.upper()))
            if sw1 == 0x61:
                data, sw1, sw2 = conn.transmit(toBytes("00C00000") + [sw2])
                result = toHexString(data).replace(" ", "")
                print(f"Authentication result={result}", flush=True)
                rc = result[0:2]
                if rc == "DB":  # success
                    res_length = data[1]
                    res = result[4:(4 + res_length * 2)]
                    ck_length = data[2 + res_length]
                    ck = result[(6 + res_length * 2):(6 + res_length * 2 + ck_length * 2)]
                    ik_length = data[2 + res_length + 1 + ck_length]
                    ik = result[(8 + res_length * 2 + ck_length * 2):
                                (8 + res_length * 2 + ck_length * 2 + ik_length * 2)]
                    write_status(state="AUTH_OK")
                elif rc == "DC":  # sync failure -> AUTS
                    auts = result[4:32]
                    write_status(state="AUTH_SYNC")
            else:
                print(f"Authentication failed sw={sw1:02x}{sw2:02x}", flush=True)
                write_status(state="AUTH_FAIL", detail=f"sw={sw1:02x}{sw2:02x}")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return res, ck, ik, auts


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <ini-file>")
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(sys.argv[1])
    cfg_endpoint = config.sections()[0]
    cfg_reader = config.get(cfg_endpoint, "reader")
    cfg_host = config.get(cfg_endpoint, "host")
    cfg_username = config.get(cfg_endpoint, "username")
    cfg_secret = config.get(cfg_endpoint, "secret")
    print(f"Endpoint={cfg_endpoint} reader={cfg_reader} host={cfg_host} user={cfg_username}")
    write_status(state="STARTING")

    manager = Manager(loop=asyncio.get_event_loop(), host=cfg_host,
                      username=cfg_username, secret=cfg_secret)

    @manager.register_event("FullyBooted")
    def on_booted(manager, message):
        print("Asterisk ready, triggering registration...")
        manager.send_action({"Action": "PJSIPRegister", "Registration": cfg_endpoint})

    @manager.register_event("AuthRequest")
    def on_auth(manager, message):
        algo = message.Algorithm
        rand = message.RAND
        autn = message.AUTN
        print(f"AuthRequest: Algorithm={algo} RAND={rand} AUTN={autn}")
        res, ck, ik, auts = read_res_ck_ik(cfg_reader, rand, autn)
        if res is not None:
            manager.send_action({"Action": "AuthResponse", "Registration": cfg_endpoint,
                                 "RES": res, "CK": ck, "IK": ik})
        elif auts is not None:
            manager.send_action({"Action": "AuthResponse", "Registration": cfg_endpoint,
                                 "AUTS": auts})
        else:
            manager.send_action({"Action": "AuthResponse", "Registration": cfg_endpoint})
        print(f"AuthResponse sent: RES={res} CK={ck} IK={ik} AUTS={auts}")

    @manager.register_event("Newchannel")
    def on_newchannel(manager, message):
        context = message.Context
        channel = message.Channel
        time.sleep(0.5)
        if context == cfg_endpoint:
            manager.send_action({"Action": "DedicatedBearerStatus", "Channel": channel,
                                 "Status": "Up"})
            print(f"DedicatedBearerStatus sent: Channel={channel}")

    manager.connect()
    try:
        manager.loop.run_forever()
    except KeyboardInterrupt:
        manager.loop.close()


if __name__ == "__main__":
    main()
