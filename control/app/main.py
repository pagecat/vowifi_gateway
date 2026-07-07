"""
main.py - VoWiFi gateway control surface (FastAPI).

Serves the management REST API + WebSocket live feed + the built WebUI, and (for the
browser softphone) proxies provisioning. Runs natively or in a container; talks to
engine containers via the Docker SDK (engine.py) and Asterisk AMI (ami.py). HTTPS with
an auto-generated self-signed cert by default.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
import random
import re
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from . import config as cfg
from . import store, engine, status as status_mod, sim, card, notify_push
from .ami import AmiClient

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vowifi.main")

WEBUI_DIR = os.environ.get("VOWIFI_WEBUI", os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "webui", "dist"))


class Hub:
    """Holds AMI clients per instance and broadcasts events to WebSocket clients."""
    def __init__(self):
        self.ami: dict[str, AmiClient] = {}
        self.clients: set[WebSocket] = set()
        self.cards: dict[str, dict] = {}     # reader NAME -> detected card/reader info
        self.scanned = False                 # card_monitor completed its first scan
        self._learning: set[str] = set()     # instances currently learning MSISDN
        self._msisdn_tries: dict[str, int] = {}
        self.health: dict[str, dict] = {}    # per-instance retry/health tracking
        self._pushed_calls: set[int] = set() # call-record ids already push-notified (dedupe)

    def cards_list(self) -> list[dict]:
        """Reader/card entries sorted by current PC/SC index (the UI display order)."""
        return sorted(self.cards.values(),
                      key=lambda c: (c.get("index") is None, c.get("index") or 0,
                                     c.get("name") or ""))

    def health_for(self, iid: str) -> dict:
        return self.health.setdefault(str(iid), {
            "fail_start": None, "retry_count": 0, "frozen_code": None,
            "frozen_reason": None, "last_state": None,
        })

    def reset_health(self, iid: str):
        self.health[str(iid)] = {"fail_start": None, "retry_count": 0, "frozen_code": None,
                                 "frozen_reason": None, "last_state": None}


    async def broadcast(self, msg: dict):
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    async def ami_for(self, iid: str) -> AmiClient | None:
        iid = str(iid)
        inst = cfg.get_instance(iid)
        if not inst or not engine.is_running(iid):
            return None
        client = self.ami.get(iid)
        ip = engine.container_ip(iid)
        if not ip:
            return None
        if client and client.connected and client.host == ip:
            return client
        # (re)connect
        if client:
            await client.close()
        client = AmiClient(iid, ip, 5038, inst.get("ami_user", "vowifi"),
                           inst["ami_secret"], realm=cfg.ims_realm(inst["mcc"], inst["mnc"]),
                           msisdn=inst.get("msisdn", ""), smsc=inst.get("smsc", ""))
        await client.connect()
        self.ami[iid] = client
        return client


hub = Hub()


def _match_instance_by_iccid(iccid):
    if not iccid:
        return None
    for i in cfg.list_instances():
        if i.get("iccid") == iccid:
            return i
    return None


def _random_svn() -> str:
    """Random 2-digit Software Version Number for an auto-derived IMEISV."""
    return f"{random.randint(0, 99):02d}"


def _find_running_by_reader(name: str):
    """The running instance whose pin_keeper reports using this reader NAME
    (pin_status.json "reader") — per-reader correct with multiple SIMs."""
    if not name:
        return None
    for i in cfg.list_instances():
        if not engine.is_running(str(i["id"])):
            continue
        ps = engine.read_run_json(str(i["id"]), "pin_status.json") or {}
        if ps.get("reader") == name:
            return i
    return None


async def _on_card_insert(name, idx):
    info = {"index": idx, "name": name, "present": True, "iccid": None,
            "pin_enabled": None, "pin_tries": None, "matched": None, "imsi": None,
            "mcc": None, "mnc": None, "smsc": None}
    # A running engine may already hold this card (manager restart, or pcscd flapped
    # while the engine kept running) — probing it could clash with the engine's card
    # access. Always map the reader to the running instance whose pin_keeper reports
    # using THIS reader name first, and only probe when no running engine claims it.
    inst = await asyncio.to_thread(_find_running_by_reader, name)
    if inst is not None:
        info.update(iccid=inst.get("iccid"), imsi=inst.get("imsi"), matched=inst["id"],
                    smsc=inst.get("smsc"))
    else:
        try:
            c = await asyncio.to_thread(sim.read_card, idx)
            info.update(iccid=c.iccid, pin_enabled=c.pin_enabled, pin_tries=c.pin_tries,
                        imsi=c.imsi, mcc=c.mcc, mnc=c.mnc, smsc=c.smsc)
        except Exception as e:  # noqa
            log.debug("card probe failed: %r", e)
        inst = _match_instance_by_iccid(info["iccid"])
        if inst:
            info["matched"] = inst["id"]
            info["imsi"] = info["imsi"] or inst.get("imsi")
    hub.cards[name] = info
    log.info("card inserted reader=%s (%s) iccid=%s matched=%s", idx, name,
             info["iccid"], info["matched"])
    # NOTE: we deliberately do NOT auto-start the matched line here. A card (re)appearing
    # — after an unplug, a reader drop, or a manual Stop — leaves the line stopped and
    # waiting for the user to press Start / Re-provision on the dashboard. Only failures
    # that occur DURING an active registration flow trigger the bounded auto-retry
    # (apply_health, max n attempts). This avoids an endless insert->start->fail->stop
    # loop and respects a deliberate manual stop.


async def _on_card_remove(entry: dict, reader_unplugged: bool = False) -> bool:
    """Card pulled from a reader, or (reader_unplugged) the whole reader disconnected.
    Stops the SIP engine container serving that card. The entry must be the reader's
    LAST-KNOWN state (name/matched/iccid) — the caller must not blank it first.
    Returns True when a running line was stopped."""
    name, idx = entry.get("name", ""), entry.get("index")
    matched, iccid = entry.get("matched"), entry.get("iccid")
    if not reader_unplugged:
        hub.cards[name] = {"index": idx, "name": name, "present": False, "iccid": None,
                           "matched": None, "imsi": None, "pin_enabled": None,
                           "pin_tries": None}
    log.info("%s reader=%s (%s) (was iccid=%s matched=%s)",
             "reader unplugged" if reader_unplugged else "card removed",
             idx, name, iccid, matched)
    target = None
    if matched:
        target = cfg.get_instance(matched)
    if target is None and iccid:
        target = _match_instance_by_iccid(iccid)
    if target is None:
        # Unknown/unmatched identity: map by the reader NAME the running engine reports
        # using (pin_status.json). This is the only safe fallback — guessing "the single
        # running instance" could stop a healthy line on ANOTHER reader.
        target = await asyncio.to_thread(_find_running_by_reader, name)
    if target and await asyncio.to_thread(engine.is_running, str(target["id"])):
        # Stop the SIP server + docker container on card/reader removal.
        await asyncio.to_thread(engine.stop, str(target["id"]))
        c = hub.ami.pop(str(target["id"]), None)
        if c:
            await c.close()
        await hub.broadcast({"type": "engine", "instance": target["id"],
                             "event": "reader_lost" if reader_unplugged else "card_removed",
                             "args": [name]})
        await hub.broadcast({"type": "status", "instance": str(target["id"]),
                             "state": "NO_CARD",
                             "label": "Reader unplugged" if reader_unplugged
                                      else "No SIM card (removed)",
                             "detail": {}})
        return True
    return False


async def card_monitor():
    """Real-time monitor for BOTH reader hotplug (plug/unplug) and card insert/remove.
    State is keyed by reader NAME: PC/SC indices shift when a reader is unplugged, so
    names are the stable identity; each entry's `index` field is refreshed every scan for
    the API calls that take reader_index. Between scans it blocks in
    card.wait_for_change (PnP-aware SCardGetStatusChange), so hotplug is reflected
    near-instantly without hammering pcscd."""
    first = True
    while True:
        try:
            states = await asyncio.to_thread(card.reader_states)
            if states is None:
                # Transient PC/SC error (pcscd restarting?) — NOT "all readers gone".
                # Skip this cycle; keep known state and engines untouched.
                log.debug("card monitor: PC/SC unavailable, skipping scan")
                await asyncio.sleep(1.2)
                continue
            current = {st["name"]: st for st in states}
            changed = False

            # reader unplugged -> drop its row + stop any engine bound to it
            for name in [n for n in hub.cards if n not in current]:
                entry = hub.cards.pop(name)
                stopped = await _on_card_remove(entry, reader_unplugged=True)
                if not stopped:
                    # _on_card_remove already broadcast the (more informative)
                    # "reader_lost — line stopped" event; only emit the generic one
                    # when no line was affected, so the UI shows a single toast.
                    await hub.broadcast({"type": "engine", "instance": "",
                                         "event": "reader_removed", "args": [name]})
                changed = True

            for name, st in current.items():
                entry = hub.cards.get(name)
                if entry is None:
                    # reader newly plugged in (or first scan after manager start)
                    if not first:
                        log.info("reader plugged in: %s", name)
                        await hub.broadcast({"type": "engine", "instance": "",
                                             "event": "reader_added", "args": [name]})
                    if st["present"]:
                        await _on_card_insert(name, st["index"])
                    else:
                        hub.cards[name] = {**st, "iccid": None, "matched": None,
                                           "imsi": None, "pin_enabled": None,
                                           "pin_tries": None}
                    changed = True
                    continue
                if entry.get("index") != st["index"]:
                    entry["index"] = st["index"]     # indices shift on unplug
                    changed = True
                if bool(entry.get("present")) != st["present"]:
                    if st["present"]:
                        await _on_card_insert(name, st["index"])
                    else:
                        await _on_card_remove(entry)
                    changed = True
            if changed:
                await hub.broadcast({"type": "cards", "cards": hub.cards_list()})
            # Only a completed scan counts: a failed first scan must retry as "first"
            # (readers seen later may belong to already-running engines).
            hub.scanned = True
            first = False
        except Exception as e:  # noqa
            log.debug("card monitor error: %r", e)
        # Instant wake on any reader/card change; the timeout bounds the worst case for
        # changes that slip between a scan and the next wait (fresh-snapshot window).
        # The short sleep bounds the rescan rate if something reports changes endlessly.
        await asyncio.to_thread(card.wait_for_change, 2.5)
        await asyncio.sleep(0.25)


def extract_msisdn(iid):
    """Learn the registered MSISDN from the P-Associated-URI in the engine SIP logs."""
    logs = engine.logs(iid, 1200)
    m = re.search(r'P-Associated-Uri:\s*<(?:tel:|sip:)(\+\d+)', logs, re.I)
    return m.group(1) if m else None


async def learn_msisdn(iid):
    """One-shot: enable the SIP logger, re-register to produce a fresh 200 OK, then parse
    the P-Associated-URI. Capped attempts so we don't re-register forever."""
    try:
        await asyncio.to_thread(engine.exec_cli, iid, "pjsip set logger on")
        await asyncio.to_thread(engine.exec_cli, iid, "pjsip send register volte_ims")
        await asyncio.sleep(8)
        msisdn = await asyncio.to_thread(extract_msisdn, iid)
        if msisdn:
            cfg.upsert_instance({"id": iid, "msisdn": msisdn})
            c = hub.ami.get(iid)
            if c:
                c.msisdn = msisdn
            log.info("learned MSISDN %s for instance %s", msisdn, iid)
            await hub.broadcast({"type": "engine", "instance": iid, "event": "msisdn", "args": [msisdn]})
    except Exception as e:  # noqa
        log.debug("learn_msisdn error: %r", e)
    finally:
        hub._learning.discard(iid)


async def status_poller():
    while True:
        try:
            for inst in cfg.list_instances():
                iid = str(inst["id"])
                ami = await hub.ami_for(iid)
                st = await status_mod.compute(inst, ami)
                if st["state"] == "OK" and not inst.get("msisdn") \
                        and iid not in hub._learning and hub._msisdn_tries.get(iid, 0) < 4:
                    hub._learning.add(iid)
                    hub._msisdn_tries[iid] = hub._msisdn_tries.get(iid, 0) + 1
                    asyncio.create_task(learn_msisdn(iid))
                st = apply_health(iid, inst, st)
                await hub.broadcast({"type": "status", "instance": iid, **st})
        except Exception as e:  # noqa
            log.debug("poller error: %r", e)
        await asyncio.sleep(4)


def _frozen(h, st, rmax):
    return {"state": "ERROR", "label": status_mod.LABELS["ERROR"],
            "reason_code": h["frozen_code"], "reason": h["frozen_reason"],
            "detail": st.get("detail", {}), "retry": {"count": rmax, "max": rmax},
            "frozen": True}


def apply_health(iid, inst, st):
    """Overlay bounded auto-retry state. After max attempts of continuous failure (with the
    SIM still present) the engine is stopped and the status frozen to ERROR + reason, until
    the user retries/re-provisions or the card is re-inserted."""
    rcfg = inst.get("retry") or cfg.get_settings().get("retry", {})
    rmax = max(1, int(rcfg.get("max", 3)))
    rint = max(5, int(rcfg.get("interval", 40)))
    h = hub.health_for(iid)
    state = st["state"]

    if state == "OK":
        hub.reset_health(iid)
        st["retry"] = {"count": 0, "max": rmax}
        return st
    if h.get("frozen_code"):
        return _frozen(h, st, rmax)
    if state == "STOPPED":
        st["retry"] = {"count": 0, "max": rmax}
        return st
    if state == "NO_CARD":
        # SIM removed/absent -> handled by the card monitor; don't count as a retry.
        h["fail_start"] = None
        h["retry_count"] = 0
        st["retry"] = {"count": 0, "max": rmax}
        return st
    if state == "PIN_PROBLEM":
        # wrong/blocked PIN won't recover by retrying — surface immediately.
        h["frozen_code"] = st["reason_code"]
        h["frozen_reason"] = st["reason"]
        return _frozen(h, st, rmax)

    # EPDG_UNRESOLVED / TUNNEL_DOWN / REGISTERING -> the engine keeps retrying internally;
    # we bound the total time and then give up.
    now = time.monotonic()
    if h["fail_start"] is None:
        h["fail_start"] = now
    elapsed = now - h["fail_start"]
    count = min(rmax, int(elapsed // rint) + 1)
    h["retry_count"] = count
    if elapsed >= rmax * rint:
        h["frozen_code"] = st["reason_code"]
        h["frozen_reason"] = st["reason"]
        try:
            engine.stop(iid)
        except Exception:
            pass
        c = hub.ami.pop(str(iid), None)
        if c:
            asyncio.create_task(c.close())
        return _frozen(h, st, rmax)
    st["retry"] = {"count": count, "max": rmax}
    return st


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init()
    poller = asyncio.create_task(status_poller())
    monitor = asyncio.create_task(card_monitor())
    yield
    poller.cancel()
    monitor.cancel()
    # Reap the cancelled tasks (the monitor may be parked in a to_thread wait for up to
    # its timeout; awaiting keeps shutdown deterministic instead of leaking the error).
    await asyncio.gather(poller, monitor, return_exceptions=True)
    for c in hub.ami.values():
        await c.close()


app = FastAPI(title="VoWiFi Gateway", lifespan=lifespan)


# ----------------------------- SIM / readers -----------------------------
@app.get("/api/readers")
def api_readers():
    return {"readers": sim.list_readers()}


@app.get("/api/sim/detect")
def api_sim_detect(reader_index: int = 0):
    return sim.read_card(reader_index).dict()


def _resolve_reader_index(body: dict) -> int:
    """Resolve the target reader for index-taking SIM APIs. When the caller supplies the
    reader NAME we re-resolve the index at request time — PC/SC indices shift when a
    reader is unplugged, so a UI-cached index may point at a DIFFERENT physical reader
    (and e.g. burn a PIN try on the wrong SIM)."""
    idx = int(body.get("reader_index", 0))
    rname = body.get("reader")
    if rname:
        rlist = sim.list_readers()
        if rname not in rlist:
            raise HTTPException(409, f"reader '{rname}' is no longer connected")
        idx = rlist.index(rname)
    return idx


@app.post("/api/sim/verify-pin")
async def api_verify_pin(body: dict):
    idx = await asyncio.to_thread(_resolve_reader_index, body)
    res = await asyncio.to_thread(sim.verify_pin, body["pin"], idx)
    if res.get("ok"):
        # PIN now satisfied — re-read the (previously locked) IMSI + SMSC and refresh the
        # detected-card entry so the dashboard can move from "locked" to "ready to provision".
        try:
            c = await asyncio.to_thread(sim.read_card, idx, body["pin"])
            # Key strictly by the reader NAME the read actually used — an index-keyed
            # lookup could merge this card's identity into a stale entry of a reader
            # that was just unplugged.
            card_entry = hub.cards.get(c.reader) or {"index": idx, "name": c.reader,
                                                     "present": True}
            card_entry.update(present=True, iccid=c.iccid, imsi=c.imsi, mcc=c.mcc,
                              mnc=c.mnc, pin_enabled=c.pin_enabled, pin_tries=c.pin_tries,
                              smsc=c.smsc)
            inst = _match_instance_by_iccid(c.iccid)
            card_entry["matched"] = inst["id"] if inst else None
            hub.cards[c.reader] = card_entry
            res["card"] = card_entry
            await hub.broadcast({"type": "cards", "cards": hub.cards_list()})
        except Exception as e:  # noqa
            log.debug("post-verify re-read failed: %r", e)
    return res


@app.post("/api/sim/change-pin")
async def api_change_pin(body: dict):
    return sim.change_pin(body["old"], body["new"], body.get("reader_index", 0))


@app.post("/api/sim/pin-enabled")
async def api_pin_enabled(body: dict):
    return sim.set_pin_enabled(body["pin"], bool(body["enabled"]), body.get("reader_index", 0))


def _refresh_card_matches():
    """Recompute each detected card's matched instance against current config. Only for
    entries whose ICCID is known — entries mapped via a running engine's pin_status
    (identity not probed) must keep that match instead of being wiped to None."""
    for c in hub.cards.values():
        if c.get("present") and c.get("iccid"):
            inst = _match_instance_by_iccid(c.get("iccid"))
            c["matched"] = inst["id"] if inst else None


@app.get("/api/cards")
async def api_cards():
    """Physically detected readers/cards (from the real-time monitor)."""
    if not hub.scanned:
        # The monitor hasn't finished its first scan yet (manager just started) — answer
        # from a live reader scan so the UI never sees a false "no readers" flash. Map
        # present cards to running engines by pin_status reader name (no card access).
        def scan():
            out = []
            for st in card.reader_states() or []:
                inst = _find_running_by_reader(st["name"]) if st["present"] else None
                out.append({**st,
                            "iccid": inst.get("iccid") if inst else None,
                            "imsi": inst.get("imsi") if inst else None,
                            "matched": inst["id"] if inst else None,
                            "pin_enabled": None, "pin_tries": None})
            return out
        return {"cards": await asyncio.to_thread(scan)}
    _refresh_card_matches()
    return {"cards": hub.cards_list()}


@app.get("/api/ports/suggest")
def api_ports_suggest():
    """Preview the SIP port the automatic allocator would pick for a NEW line right now
    (conflict-checked against other lines + live host listeners). Lets the manual-port UI
    show a sensible default and the auto option show what it will use."""
    try:
        block = cfg.alloc_ports_auto(cfg.load())
        return {"auto_sip_udp": block["sip_udp"], "auto_sip_tls": block["sip_tls"],
                "min": cfg.MIN_USER_PORT, "max": cfg.MAX_USER_PORT}
    except Exception as e:  # noqa
        raise HTTPException(409, f"no free port block: {e}")


def _reader_index_for_instance(inst: dict) -> int | None:
    """Find the PC/SC reader index currently holding this instance's SIM (match by ICCID
    against the live card monitor). Returns None if the card isn't present."""
    iccid = inst.get("iccid")
    for c in hub.cards.values():
        if c.get("present") and iccid and c.get("iccid") == iccid:
            return c.get("index")
    return None


def _preflight_pin(inst: dict) -> dict:
    """Actively check the SIM's PIN state BEFORE starting the engine (so we never spin up
    strongSwan/IMS against a locked card). Reads the physical card:
      - card absent                         -> {ok:False, code:'no_card'}
      - PIN not required (disabled)          -> {ok:True,  need_pin:False}
      - PIN required, no saved PIN           -> {ok:False, code:'pin_required'}
      - PIN required, saved PIN verifies     -> {ok:True,  need_pin:True}
      - PIN required, saved PIN wrong/blocked -> {ok:False, code:'pin_invalid', clear:True}
    On 'pin_invalid' the saved PIN is stale and should be cleared so the user re-enters it.
    If the card can't be located/read we fail OPEN (ok:True) rather than block a start that
    might otherwise work (e.g. an engine already holds the card)."""
    idx = _reader_index_for_instance(inst)
    if idx is None:
        # Card not seen by the monitor — could be held by a running engine, or truly gone.
        # Don't block here; engine start + status FSM will surface NO_CARD if it's absent.
        return {"ok": True, "need_pin": bool(inst.get("pin"))}
    try:
        probe = sim.read_card(idx)          # no VERIFY: learns pin_enabled + presence
    except Exception as e:  # noqa
        log.debug("preflight probe failed: %r", e)
        return {"ok": True, "need_pin": bool(inst.get("pin"))}
    if not probe.present:
        return {"ok": False, "code": "no_card"}
    if probe.pin_enabled is False:
        return {"ok": True, "need_pin": False}
    # PIN is (or may be) required.
    saved = inst.get("pin")
    if not saved:
        return {"ok": False, "code": "pin_required",
                "tries": probe.pin_tries}
    # Verify the saved PIN actually works (single connection: read_card VERIFYs then reads).
    try:
        chk = sim.read_card(idx, saved)
    except Exception as e:  # noqa
        log.debug("preflight verify failed: %r", e)
        return {"ok": True, "need_pin": True}     # couldn't verify now; let the engine try
    if chk.error and "PIN" in (chk.error or "").upper():
        return {"ok": False, "code": "pin_invalid", "clear": True, "tries": chk.pin_tries}
    return {"ok": True, "need_pin": True}


@app.post("/api/provision")
async def api_provision(body: dict):
    """Provision a detected card: verify PIN, read identity, create the line and start it.
    Required: pin, imei. Optional: imeisv (auto-derived from imei if blank), name, smsc,
    reader_index, reader (name), sip, webrtc, id, port_mode ('auto'|'manual'), sip_port
    (int, when manual)."""
    idx = await asyncio.to_thread(_resolve_reader_index, body)
    pin = body.get("pin", "")
    c = await asyncio.to_thread(sim.read_card, idx, pin or None)
    if c.error and "PIN" in (c.error or "").upper():
        raise HTTPException(400, f"PIN error: {c.error} ({c.pin_tries} tries left)")
    if not c.imsi:
        raise HTTPException(400, "could not read IMSI (is the PIN correct?)")
    sip = body.get("sip") or {"listen_addr": "0.0.0.0", "transport": "udp", "external": []}
    sip.setdefault("webrtc", {"enable": bool(body.get("webrtc", True))})
    # SMSC: manual override wins; otherwise read from the SIM (EF_SMSP, authoritative).
    # If the SIM can't provide it we ask the user to type it (no carrier presets).
    smsc = (body.get("smsc") or "").strip() or c.smsc
    if not smsc:
        raise HTTPException(422, "smsc_unreadable: could not read the SMS centre from the SIM — "
                                 "please provide it manually.")
    inst = {
        "id": str(body.get("id") or (len(cfg.list_instances()) + 1)),
        "name": body.get("name") or f"{c.mcc}-{c.mnc}",
        "imsi": c.imsi, "mcc": c.mcc, "mnc": c.mnc, "iccid": c.iccid,
        "imei": body.get("imei", ""),
        # IMEISV for DEVICE_IDENTITY: user value if provided, else auto-derive (14-digit IMEI
        # base + random 2-digit SVN) so each line looks like a distinct handset build.
        "imeisv": (body.get("imeisv") or "").strip()
                  or cfg.imeisv_from_imei(body.get("imei", ""), svn=_random_svn()),
        "pin": pin,
        "reader": f"imsi:{c.imsi}",
        "reader_index": idx,  # store the physical reader index for USB device passthrough
        "smsc": smsc,
        "msisdn": body.get("msisdn", ""),
        "enabled": True, "sip": sip,
        "debug": body.get("debug") or {"asterisk": True, "charon": False},
    }
    # Port mapping: 'manual' pins the SIP UDP port the user chose (the rest of the block
    # derives from it, validated for range + host/instance conflicts). 'auto' (default)
    # allocates a conflict-free block now — and when re-provisioning an existing line it
    # RE-allocates (so switching an already-provisioned line back to Auto actually moves it
    # off a manual port), stepping past anything in use.
    iid = str(inst["id"])
    if body.get("port_mode") == "manual":
        try:
            inst["ports"] = cfg.ports_from_sip_base(cfg.load(), int(body.get("sip_port", 0)),
                                                    exclude_iid=iid)
        except (ValueError, TypeError) as e:
            raise HTTPException(422, f"port_error: {e}")
    else:
        try:
            inst["ports"] = cfg.alloc_ports_auto(cfg.load(), exclude_iid=iid)
        except ValueError as e:
            raise HTTPException(422, f"port_error: {e}")
    inst = cfg.upsert_instance(inst)
    hub._msisdn_tries.pop(str(inst["id"]), None)
    hub.reset_health(inst["id"])
    await asyncio.to_thread(engine.start, inst, cfg.get_settings(),
                            dev_mounts=os.environ.get("VOWIFI_DEV_MOUNTS", "") == "1")
    _refresh_card_matches()
    await hub.broadcast({"type": "cards", "cards": hub.cards_list()})
    safe = {k: v for k, v in inst.items() if k != "pin"}
    return {"ok": True, "instance": safe}


# ----------------------------- settings -----------------------------
@app.get("/api/settings")
def api_get_settings():
    return cfg.get_settings()


@app.put("/api/settings")
def api_put_settings(body: dict):
    return cfg.update_settings(body)


# ----------------------------- instances -----------------------------
@app.get("/api/instances")
async def api_instances():
    out = []
    for inst in cfg.list_instances():
        ami = await hub.ami_for(str(inst["id"]))
        st = await status_mod.compute(inst, ami)
        st = apply_health(str(inst["id"]), inst, st)
        safe = {k: v for k, v in inst.items() if k != "pin"}
        safe["has_pin"] = bool(inst.get("pin"))
        # Report the reader index that PHYSICALLY holds this line's SIM right now (ICCID-matched
        # against the live monitor) instead of the stored one. PC/SC indices shift when readers
        # are unplugged, so a stored index can be stale and make the SIM-config "Detect card"
        # button probe a reader that no longer exists ("No SIM card in reader N").
        live_idx = _reader_index_for_instance(inst)
        if live_idx is not None:
            safe["reader_index"] = live_idx
        out.append({**safe, "status": st})
    return {"instances": out}


@app.post("/api/instances")
async def api_instance_upsert(body: dict):
    if "id" not in body:
        raise HTTPException(400, "id required")
    iid = str(body["id"])
    was_running = await asyncio.to_thread(engine.is_running, iid)
    inst = cfg.upsert_instance(body)
    applied = False
    # A running line holds its config in the engine container (rendered instance.json:
    # pjsip accounts, IMEI, SMSC, User-Agent, …). Editing the config alone doesn't reach
    # the running Asterisk — so restart the container to re-render + reload the new config.
    if was_running:
        try:
            hub._msisdn_tries.pop(iid, None)
            hub.reset_health(iid)
            c = hub.ami.pop(iid, None)
            if c:
                await c.close()
            await asyncio.to_thread(engine.start, inst, cfg.get_settings(),
                                    dev_mounts=os.environ.get("VOWIFI_DEV_MOUNTS", "") == "1")
            applied = True
            asyncio.create_task(push_status(iid))
        except Exception as e:  # noqa
            log.warning("apply-on-save restart failed for %s: %r", iid, e)
    safe = {k: v for k, v in inst.items() if k != "pin"}
    safe["applied"] = applied      # true => config was re-applied to the running engine
    return safe


@app.delete("/api/instances/{iid}")
async def api_instance_delete(iid: str):
    engine.stop(iid)
    c = hub.ami.pop(str(iid), None)
    if c:
        await c.close()
    cfg.delete_instance(iid)
    _refresh_card_matches()
    await hub.broadcast({"type": "cards", "cards": hub.cards_list()})
    return {"ok": True}


@app.post("/api/instances/{iid}/start")
async def api_instance_start(iid: str, body: dict | None = None):
    """Start (or restart) a line. Actively checks the SIM PIN state first: if the card
    requires a PIN and we have no valid saved one, the start is refused with a structured
    error so the UI can prompt for the PIN — we never bring up the IPsec/IMS engine against
    a locked card. A PIN supplied in the body (re-entry) is verified, saved, and used."""
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")

    # If the caller re-supplied a PIN (unlock flow), verify + persist it before preflight.
    supplied = (body or {}).get("pin")
    if supplied:
        idx = await asyncio.to_thread(_reader_index_for_instance, inst)
        if idx is not None:
            chk = await asyncio.to_thread(sim.read_card, idx, supplied)
            if chk.error and "PIN" in (chk.error or "").upper():
                raise HTTPException(400, f"PIN error: {chk.error}"
                                         + (f" ({chk.pin_tries} tries left)" if chk.pin_tries is not None else ""))
        inst = cfg.upsert_instance({"id": str(iid), "pin": supplied})

    pf = await asyncio.to_thread(_preflight_pin, inst)
    if not pf["ok"]:
        if pf.get("clear"):
            cfg.clear_pin(str(iid))     # stale saved PIN — force re-entry next time
        raise HTTPException(409, {"code": pf["code"], "tries": pf.get("tries")})

    settings = cfg.get_settings()
    dev = os.environ.get("VOWIFI_DEV_MOUNTS", "") == "1"
    hub._msisdn_tries.pop(str(iid), None)
    hub.reset_health(iid)
    cid = await asyncio.to_thread(engine.start, inst, settings, dev_mounts=dev)
    asyncio.create_task(push_status(str(iid)))
    return {"ok": True, "container": cid}


@app.post("/api/instances/{iid}/reprovision")
async def api_reprovision(iid: str, body: dict | None = None):
    """Manual re-provision: reset retry state and re-establish the line using the stored
    config (re-reads the SIM, no PIN re-entry). Optional body overrides fields (e.g. sip
    user_agent) before restart. Runs the same PIN preflight as start."""
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")
    if body:
        inst = cfg.upsert_instance({"id": str(iid), **body})
    pf = await asyncio.to_thread(_preflight_pin, inst)
    if not pf["ok"]:
        if pf.get("clear"):
            cfg.clear_pin(str(iid))
        raise HTTPException(409, {"code": pf["code"], "tries": pf.get("tries")})
    hub._msisdn_tries.pop(str(iid), None)
    hub.reset_health(iid)
    dev = os.environ.get("VOWIFI_DEV_MOUNTS", "") == "1"
    cid = await asyncio.to_thread(engine.start, inst, cfg.get_settings(), dev_mounts=dev)
    asyncio.create_task(push_status(str(iid)))
    return {"ok": True, "container": cid}


@app.post("/api/instances/{iid}/pin/clear")
async def api_clear_pin(iid: str):
    """Delete the saved SIM PIN for a line. If it's running, stop it — the next start must
    re-run the PIN flow (the whole point of forgetting the PIN)."""
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")
    had = cfg.clear_pin(str(iid))
    if await asyncio.to_thread(engine.is_running, str(iid)):
        await asyncio.to_thread(engine.stop, str(iid))
        c = hub.ami.pop(str(iid), None)
        if c:
            await c.close()
        asyncio.create_task(push_status(str(iid)))
    return {"ok": True, "had_pin": had}


@app.post("/api/instances/{iid}/stop")
def api_instance_stop(iid: str):
    engine.stop(iid)
    return {"ok": True}


@app.get("/api/instances/{iid}/status")
async def api_instance_status(iid: str):
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")
    ami = await hub.ami_for(iid)
    st = await status_mod.compute(inst, ami)
    return apply_health(str(iid), inst, st)


@app.get("/api/instances/{iid}/logs")
def api_instance_logs(iid: str, tail: int = 200):
    return {"engine": engine.logs(iid, tail),
            "charon": _read_run_text(iid, "charon.log", 200)}


def _read_run_text(iid, name, tail):
    path = os.path.join(cfg.DATA_DIR, "instances", str(iid), "run", name)
    try:
        with open(path) as f:
            return "".join(f.readlines()[-tail:])
    except Exception:
        return ""


@app.post("/api/instances/{iid}/register")
async def api_instance_register(iid: str):
    return {"output": engine.exec_cli(iid, "pjsip send register volte_ims")}


# ----------------------------- SMS -----------------------------
@app.get("/api/instances/{iid}/messages/threads")
def api_threads(iid: str):
    return {"threads": store.list_threads(iid)}


@app.get("/api/instances/{iid}/messages/{peer}")
def api_messages(iid: str, peer: str):
    return {"messages": store.list_messages(iid, peer)}


@app.post("/api/instances/{iid}/messages/delete")
async def api_messages_delete(iid: str, body: dict):
    """Delete messages. Body: {ids:[...]} for specific messages, {peer:"..."} for a whole
    conversation, or {all:true} to wipe every message on the line. Broadcasts a refresh."""
    if body.get("all"):
        n = await asyncio.to_thread(store.clear_messages, iid)
    elif body.get("peer") is not None:
        n = await asyncio.to_thread(store.delete_thread, iid, body["peer"])
    elif body.get("ids"):
        n = await asyncio.to_thread(store.delete_messages, iid, body["ids"])
    else:
        raise HTTPException(400, "provide ids, peer, or all")
    await hub.broadcast({"type": "sms", "instance": str(iid), "deleted": n})
    return {"ok": True, "deleted": n}


SMS_RESP_RE = re.compile(r"Received SIP response")


def detect_sms_result(iid: str) -> dict:
    """Determine the real MO SMS outcome from the SIP response the network returned.
    AMI 'Success' only means Asterisk accepted the send; the carrier's 2xx/4xx comes
    asynchronously. Returns {ok: True|False|None, code, reason}."""
    raw = engine.logs(iid, 300)
    raw = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    blocks = SMS_RESP_RE.split(raw)
    result = {"ok": None}
    for b in blocks[1:]:
        m = re.search(r"SIP/2\.0 (\d{3})([^\n]*)", b)
        if not m:
            continue
        if re.search(r"CSeq:\s*\d+\s+MESSAGE", b):   # a response to our MESSAGE
            code = int(m.group(1))
            result = {"ok": 200 <= code < 300, "code": code,
                      "reason": m.group(2).strip()}
    return result


@app.post("/api/instances/{iid}/sms/send")
async def api_sms_send(iid: str, body: dict):
    to = body["to"]
    text = body["body"]
    ami = await hub.ami_for(iid)
    if not ami:
        raise HTTPException(409, "Line is not running / control channel unavailable.")
    rec = store.add_message(iid, "out", to, text, status="pending")
    res = await ami.send_sms(to, text)

    if not res.get("ok"):
        # Asterisk itself refused to dispatch (endpoint down, bad address, etc.)
        ok, err = False, (res.get("detail") or res.get("error") or "Send rejected by the line.")
    else:
        # Wait briefly for the carrier's SIP response and read the real outcome.
        await asyncio.sleep(3)
        d = await asyncio.to_thread(detect_sms_result, iid)
        if d.get("ok") is False:
            ok = False
            err = f"Carrier rejected the SMS (SIP {d.get('code')} {d.get('reason','')}).".strip()
        else:
            ok, err = True, None   # 2xx, or accepted with no negative response seen

    status = "ok" if ok else "failed"
    store.set_message_status(rec["id"], status, err)
    rec["status"] = status
    rec["error"] = err
    await hub.broadcast({"type": "sms", "instance": str(iid), "message": rec})
    return {"ok": ok, "message": rec, "error": err}


# ----------------------------- Calls -----------------------------
@app.get("/api/instances/{iid}/calls")
def api_calls(iid: str):
    return {"calls": store.list_calls(iid)}


@app.post("/api/instances/{iid}/calls/delete")
async def api_calls_delete(iid: str, body: dict):
    """Delete call-log entries. Body: {ids:[...]} for specific calls or {all:true} to clear
    the whole log. Broadcasts a refresh so open Softphone views reload the list."""
    if body.get("all"):
        n = await asyncio.to_thread(store.clear_calls, iid)
    elif body.get("ids"):
        n = await asyncio.to_thread(store.delete_calls, iid, body["ids"])
    else:
        raise HTTPException(400, "provide ids or all")
    await hub.broadcast({"type": "call", "instance": str(iid), "deleted": n})
    return {"ok": True, "deleted": n}


@app.post("/api/instances/{iid}/call")
async def api_call(iid: str, body: dict):
    ami = await hub.ami_for(iid)
    if not ami:
        raise HTTPException(409, "instance not running")
    frm = body.get("from_endpoint", "webrtc")
    res = await ami.originate(body["to"], frm)
    store.add_call(iid, "out", body["to"], status="ringing")
    return res


@app.post("/api/instances/{iid}/hangup")
async def api_hangup(iid: str):
    ami = await hub.ami_for(iid)
    if not ami:
        raise HTTPException(409, "instance not running")
    return await ami.hangup_all()


@app.get("/api/instances/{iid}/softphone")
def api_softphone(iid: str, request: Request):
    """Provisioning for the browser softphone (JsSIP over WSS)."""
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")
    sip = inst.get("sip", {}) or {}
    wr = sip.get("webrtc", {}) or {}
    ports = inst.get("ports", {})
    host = (request.headers.get("host") or "").split(":")[0] or request.url.hostname
    return {
        "enabled": bool(wr.get("enable", True)),
        "username": wr.get("username", "webrtc"),
        "password": wr.get("password", ""),
        "ws_port": ports.get("webrtc", 8089),
        "host": host,
        "realm": cfg.ims_realm(inst["mcc"], inst["mnc"]),
    }


@app.get("/api/instances/{iid}/sipinfo")
def api_sipinfo(iid: str, request: Request):
    """Connection parameters for a standard (non-WebRTC) SIP client. The line runs an
    Asterisk endpoint per configured external account (sip.external[]); a SIP softphone
    registers to this gateway's host:port with that account's username/password and dials
    E.164 numbers, which are routed out over VoWiFi/IMS."""
    inst = cfg.get_instance(iid)
    if not inst:
        raise HTTPException(404, "no such instance")
    sip = inst.get("sip", {}) or {}
    ports = inst.get("ports", {})
    transport = sip.get("transport", "udp")
    host = (request.headers.get("host") or "").split(":")[0] or request.url.hostname
    # Host-side published port for this line's local SIP transport (container 5060/5061 is
    # mapped to an index-strided host port; see engine.start port_bindings).
    port = ports.get("sip_tls", 5061) if transport == "tls" else ports.get("sip_udp", 5060)
    accounts = [{"username": a.get("username", ""), "password": a.get("password", "")}
                for a in (sip.get("external") or []) if a.get("username")]
    return {
        "host": host,
        "domain": host,
        "port": port,
        "transport": transport,
        "accounts": accounts,
        "running": engine.is_running(str(iid)),
        # from-local passes the dialled number straight through to IMS as the callee, so
        # E.164 (with +) is what the carrier expects. Default plan: allow any number
        # unchanged. The `+`->`00` variant is offered in the UI for clients that strip +.
        "dial_plan": "x.",
        "dial_plan_plus00": r"<+:00>x.|x.",
        "msisdn": inst.get("msisdn") or "",
    }


# ----------------------------- engine event hook -----------------------------
def _sip_host(sender: str) -> str | None:
    """Extract the host part of a SIP URI sender. Handles <...> brackets, an optional
    user@ part, and bracketed IPv6 hosts (sip:[2001:db8::1]) or bare IPv6."""
    s = sender.strip().strip("<>")
    m = re.match(r"sips?:(?:[^@]*@)?(.+)$", s, re.I)
    if not m:
        return None
    host = m.group(1)
    if host.startswith("["):                       # sip:[ipv6]:port
        return host[1:].split("]", 1)[0]
    # bare IPv6 (RFC-illegal in SIP but tolerated): contains multiple ':' -> treat whole as host
    if host.count(":") >= 2:
        return host.rsplit(";", 1)[0]
    return host.split(":", 1)[0].split(";", 1)[0]  # strip :port / ;params for IPv4/FQDN


def _is_internal_sms_sender(sender: str) -> bool:
    """True if an incoming-SMS 'From' looks like an IMS-internal network node rather than a
    real subscriber: a SIP URI whose host is a bare IP address (e.g. <sip:10.183.150.10> or
    a P-CSCF IPv6). The carrier's IP-SM-GW / SMSC uses such addresses for non-user
    signalling MESSAGEs. A genuine sender is an E.164 number or alphanumeric short-code."""
    if not sender:
        return False
    host = _sip_host(sender)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _call_disposition(dialstatus: str, cause: int, direction: str = "out") -> str:
    """Map Asterisk DIALSTATUS + Q.850 hangupcause to a friendly outcome. No retry — a
    rejected/busy/no-answer call is simply recorded as such. Incoming and outgoing read the
    same DIALSTATUS differently: for an inbound call the Dial targets our local softphone, so
    BUSY/decline means WE declined and CANCEL/NOANSWER means we missed it."""
    if dialstatus == "ANSWER":
        return "answered"
    if direction == "in":
        if dialstatus == "BUSY" or cause == 21:
            return "rejected"        # local softphone actively declined
        return "missed"              # remote hung up first, no answer, or rang out
    # outgoing
    if cause == 21:                     # 603 Decline — far end actively rejected
        return "rejected"
    if cause == 17 or dialstatus == "BUSY":
        return "busy"
    if dialstatus == "NOANSWER" or cause == 19:
        return "no answer"
    if dialstatus == "CANCEL":
        return "cancelled"
    if dialstatus in ("CONGESTION", "CHANUNAVAIL"):
        return "failed"
    # empty DIALSTATUS in the hangup handler => caller hung up before/while dialing.
    return (dialstatus.lower() if dialstatus else "cancelled")


@app.post("/api/engine/event")
async def api_engine_event(payload: dict):
    """Receives notify.py callbacks from engine containers."""
    iid = str(payload.get("instance", ""))
    event = payload.get("event", "")
    args = payload.get("args", [])
    if event == "sms_in" and len(args) >= 2:
        try:
            text = base64.b64decode(args[1]).decode(errors="replace")
        except Exception:
            text = args[1]
        sender = args[0] or ""
        # Drop IMS-internal signalling MESSAGEs: the carrier's IP-SM-GW / SMSC sends empty
        # non-user MESSAGEs whose From is a bare private-IP SIP URI (e.g. <sip:10.183.150.10>)
        # rather than an E.164 / short-code sender. These are not real texts — filter them so
        # they neither persist nor surface in the UI. Only drop when BOTH the sender looks
        # like an internal node AND the body is empty, so a genuine text is never lost.
        if _is_internal_sms_sender(sender) and not text.strip():
            log.info("dropping IMS-internal SMS from %r (empty body)", sender)
            return {"ok": True, "dropped": "internal_signalling"}
        rec = store.add_message(iid, "in", sender, text)
        await hub.broadcast({"type": "sms", "instance": iid, "message": rec})
        _dispatch_push(notify_push.EV_INCOMING_SMS, iid, sender, text)
    elif event == "sms_out" and len(args) >= 2:
        pass  # already stored by the send path
    elif event == "call_in":
        # Log inbound calls even when the caller withholds/omits their number (peer "") so an
        # anonymous call still gets a record that the 'h' disposition can finalize. The IMS
        # delivers one INVITE several times (VoLTE preconditions / GRUU fork / retransmit),
        # firing call_in more than once per call — both while the record is still open AND as a
        # trailing retransmit a few seconds AFTER it was finalized. add_call_deduped coalesces
        # both into the single record so no ghost 'ringing' row is left behind.
        peer = args[0] if args else ""
        rec = store.add_call_deduped(iid, "in", peer, status="ringing")
        await hub.broadcast({"type": "call", "instance": iid, "call": rec})
        # Push-notify ONCE per real inbound call. IMS re-delivers call_in several times for
        # one call (VoLTE preconditions / GRUU fork / retransmit); add_call_deduped folds
        # them into a single record, so key the notification on that record id. An anonymous
        # first event ('') whose number arrives on a later duplicate would push before the
        # number is known — so only notify once we have the peer, or after ~4s if it stays
        # anonymous (caller genuinely withheld it).
        cid = rec.get("id")
        if cid is not None and cid not in hub._pushed_calls:
            if peer or int(time.time()) - int(rec.get("start_ts", 0)) >= 4:
                hub._pushed_calls.add(cid)
                if len(hub._pushed_calls) > 512:      # bound the dedupe set
                    hub._pushed_calls = set(list(hub._pushed_calls)[-256:])
                _dispatch_push(notify_push.EV_INCOMING_CALL, iid, rec.get("peer") or peer)
    elif event == "call_out" and args:
        rec = store.add_call(iid, "out", args[0], status="dialing")
        await hub.broadcast({"type": "call", "instance": iid, "call": rec})
    elif event == "call_result" and args:
        # New form: call_result <direction> <peer> <dialstatus> <cause> (fired from the 'h'
        # hangup handler for BOTH directions). Legacy form: call_result <peer> <dialstatus>
        # <cause> (outgoing only) — kept for engines running an older dialplan.
        if args[0] in ("in", "out"):
            direction = args[0]
            to = args[1] if len(args) > 1 else ""
            dialstatus = (args[2] if len(args) > 2 else "").upper()
            cause = int(args[3]) if len(args) > 3 and str(args[3]).isdigit() else 0
        else:
            direction = "out"
            to = args[0]
            dialstatus = (args[1] if len(args) > 1 else "").upper()
            cause = int(args[2]) if len(args) > 2 and str(args[2]).isdigit() else 0
        disp = _call_disposition(dialstatus, cause, direction)
        rec = store.update_last_call(iid, direction, to, disp)
        if not rec and to:
            # exact peer didn't match an open record (e.g. 'h' lost the number to a
            # masquerade and call_out stored a different form) — finalize the latest open
            # call of this direction instead so it never stays stuck on dialing/ringing.
            rec = store.update_last_call(iid, direction, None, disp)
        if rec:
            await hub.broadcast({"type": "call", "instance": iid, "call": rec})
    else:
        await hub.broadcast({"type": "engine", "instance": iid, "event": event, "args": args})
    # real-time: any tunnel/registration transition triggers an immediate status push
    if event in ("tunnel_up", "tunnel_down", "pcscf", "registered", "unregistered"):
        asyncio.create_task(push_status(iid))
    return {"ok": True}


async def push_status(iid: str):
    """Compute + broadcast status for a single instance immediately (event-driven)."""
    inst = cfg.get_instance(iid)
    if not inst:
        return
    try:
        ami = await hub.ami_for(iid)
        st = await status_mod.compute(inst, ami)
        st = apply_health(iid, inst, st)
        await hub.broadcast({"type": "status", "instance": str(iid), **st})
    except Exception as e:  # noqa
        log.debug("push_status error: %r", e)


def _dispatch_push(event: str, iid: str, source: str, text: str | None = None):
    """Fire outbound push notifications (webhook / Telegram) for an incoming event, off the
    event path so a slow endpoint can't stall engine-event handling. No-op unless a channel
    is enabled for this event."""
    inst = cfg.get_instance(iid)
    if not inst:
        return
    settings = cfg.get_settings()
    wh = settings.get("webhook") or {}
    tg = settings.get("telegram") or {}
    if not (wh.get("enabled") or tg.get("enabled")):
        return
    asyncio.create_task(
        asyncio.to_thread(notify_push.dispatch, settings, event, inst, source, text))


# ----------------------------- WebSocket -----------------------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive / ignore inbound
    except WebSocketDisconnect:
        hub.clients.discard(ws)
    except Exception:
        hub.clients.discard(ws)


# ----------------------------- static WebUI -----------------------------
if os.path.isdir(WEBUI_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(WEBUI_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        candidate = os.path.join(WEBUI_DIR, full_path)
        if full_path and os.path.isfile(candidate):
            return FileResponse(candidate)
        index = os.path.join(WEBUI_DIR, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
        return JSONResponse({"error": "webui not built"}, status_code=404)
