"""
store.py - SQLite persistence for SMS threads/messages and the call log.

One DB per manager at $VOWIFI_DATA/vowifi.sqlite. Messages carry the instance id so a
multi-SIM setup keeps separate conversations. New rows are broadcast to the WebSocket
layer by the caller (main.py).
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time

DATA_DIR = os.environ.get("VOWIFI_DATA", os.path.join(os.getcwd(), "data"))
DB_PATH = os.path.join(DATA_DIR, "vowifi.sqlite")
_lock = threading.Lock()


def _conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance TEXT NOT NULL,
                direction TEXT NOT NULL,        -- 'in' | 'out'
                peer TEXT NOT NULL,             -- phone number / address
                body TEXT NOT NULL,
                status TEXT DEFAULT 'ok',       -- ok|pending|failed
                ts INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_msg_inst_peer ON messages(instance, peer, ts);
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance TEXT NOT NULL,
                direction TEXT NOT NULL,        -- 'in' | 'out'
                peer TEXT NOT NULL,
                status TEXT DEFAULT '',         -- ringing|answered|ended|missed|failed
                start_ts INTEGER NOT NULL,
                end_ts INTEGER
            );
            """
        )
        # migration: per-message failure detail (added later)
        try:
            c.execute("ALTER TABLE messages ADD COLUMN error TEXT")
        except Exception:
            pass


def set_message_status(mid: int, status: str, error: str | None = None):
    with _lock, _conn() as c:
        c.execute("UPDATE messages SET status=?, error=? WHERE id=?", (status, error, mid))


def add_message(instance: str, direction: str, peer: str, body: str, status: str = "ok") -> dict:
    ts = int(time.time())
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO messages(instance,direction,peer,body,status,ts) VALUES(?,?,?,?,?,?)",
            (str(instance), direction, peer, body, status, ts),
        )
        mid = cur.lastrowid
    return {"id": mid, "instance": str(instance), "direction": direction,
            "peer": peer, "body": body, "status": status, "error": None, "ts": ts}


def list_threads(instance: str) -> list:
    with _lock, _conn() as c:
        rows = c.execute(
            """SELECT peer, MAX(ts) AS last_ts,
                      (SELECT body FROM messages m2 WHERE m2.instance=m.instance AND m2.peer=m.peer
                       ORDER BY ts DESC LIMIT 1) AS last_body,
                      COUNT(*) AS n
               FROM messages m WHERE instance=? GROUP BY peer ORDER BY last_ts DESC""",
            (str(instance),),
        ).fetchall()
    return [dict(r) for r in rows]


def list_messages(instance: str, peer: str, limit: int = 200) -> list:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM messages WHERE instance=? AND peer=? ORDER BY ts ASC LIMIT ?",
            (str(instance), peer, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


def delete_messages(instance: str, ids: list[int]) -> int:
    """Delete specific messages of this instance by id. Returns the number removed."""
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    with _lock, _conn() as c:
        cur = c.execute(
            f"DELETE FROM messages WHERE instance=? AND id IN ({_placeholders(len(ids))})",
            (str(instance), *ids),
        )
        return cur.rowcount


def delete_thread(instance: str, peer: str) -> int:
    """Delete every message in one conversation (instance + peer). Returns rows removed."""
    with _lock, _conn() as c:
        cur = c.execute("DELETE FROM messages WHERE instance=? AND peer=?",
                        (str(instance), peer))
        return cur.rowcount


def clear_messages(instance: str) -> int:
    """Delete ALL messages for this instance. Returns rows removed."""
    with _lock, _conn() as c:
        cur = c.execute("DELETE FROM messages WHERE instance=?", (str(instance),))
        return cur.rowcount


def add_call(instance: str, direction: str, peer: str, status: str = "ringing") -> dict:
    ts = int(time.time())
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO calls(instance,direction,peer,status,start_ts) VALUES(?,?,?,?,?)",
            (str(instance), direction, peer, status, ts),
        )
        cid = cur.lastrowid
    return {"id": cid, "instance": str(instance), "direction": direction,
            "peer": peer, "status": status, "start_ts": ts}


def get_open_call(instance: str, direction: str, within_s: int | None = None) -> dict | None:
    """The most recent still-open (not yet finalized) call for (instance, direction), or None.

    A softphone handles one call at a time, so an inbound INVITE that the IMS delivers more
    than once (VoLTE preconditions / GRUU fork / retransmit) fires `call_in` several times
    for the SAME call. Reusing the open record instead of inserting a new one keeps one row
    per call — otherwise every extra `call_in` leaves a ghost 'ringing' entry that the single
    `call_result` never finalizes. `within_s` bounds how old the open record may be so a
    genuinely new call (after a stale unfinalized one) still starts fresh."""
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT * FROM calls WHERE instance=? AND direction=? AND end_ts IS NULL "
            "ORDER BY start_ts DESC LIMIT 1", (str(instance), direction)).fetchone()
        if not row:
            return None
        if within_s is not None and int(time.time()) - row["start_ts"] > within_s:
            return None
        return dict(row)


def get_open_call(instance: str, direction: str, within_s: int | None = None) -> dict | None:
    """The most recent still-open (not yet finalized, end_ts IS NULL) call for (instance,
    direction), or None. `within_s` bounds how old the open record may be so a genuinely new
    call after a stale unfinalized one still starts fresh."""
    with _lock, _conn() as c:
        row = c.execute(
            "SELECT * FROM calls WHERE instance=? AND direction=? AND end_ts IS NULL "
            "ORDER BY start_ts DESC LIMIT 1", (str(instance), direction)).fetchone()
        if not row:
            return None
        if within_s is not None and int(time.time()) - row["start_ts"] > within_s:
            return None
        return dict(row)


def add_call_deduped(instance: str, direction: str, peer: str, status: str = "ringing",
                     open_within_s: int = 90) -> dict:
    """Insert an inbound-call record, coalescing concurrent duplicate `call_in` events for the
    SAME still-ringing call into ONE record.

    The IMS can deliver a call_in more than once while the call is still being set up (VoLTE
    preconditions / GRUU fork): those extra events all arrive BEFORE the call_result, so the
    record is still open (end_ts IS NULL) and is simply reused — no ghost row, and no reliance
    on any time heuristic that could swallow a genuine call-back.

    (The other historical source of duplicates — the dialplan 'h' hangup handler falling
    through to the broad `_.` pattern and firing a SECOND call_in AFTER finalization — is fixed
    at the source in extensions.conf.j2 with `h => …,Return()`, so no post-finalize dedupe is
    needed here.)

    An anonymous first call_in ('') whose number arrives on a later duplicate is filled in."""
    open_rec = get_open_call(instance, direction, within_s=open_within_s)
    # Only coalesce into an open record with a compatible peer: an anonymous dup ('') matches
    # anything; a numbered dup must match (or fill) the open record's peer. A different number
    # is a distinct call and starts its own record.
    if open_rec:
        rp = open_rec.get("peer") or ""
        if not peer or not rp or peer == rp:
            if peer and not rp:
                with _lock, _conn() as c:
                    c.execute("UPDATE calls SET peer=? WHERE id=?", (peer, open_rec["id"]))
                open_rec["peer"] = peer
            return open_rec
    return add_call(instance, direction, peer, status)


def update_call(cid: int, status: str, ended: bool = False):
    with _lock, _conn() as c:
        if ended:
            c.execute("UPDATE calls SET status=?, end_ts=? WHERE id=?",
                      (status, int(time.time()), cid))
        else:
            c.execute("UPDATE calls SET status=? WHERE id=?", (status, cid))


def update_last_call(instance: str, direction: str, peer: str | None, status: str) -> dict | None:
    """Finalize the most recent still-open call for (instance, direction[, peer]).

    peer may be None/empty: Asterisk's 'h' hangup handler loses pre-Dial channel variables
    (incl. the dialled number) when the caller hangs up mid-Dial and the channel is
    masqueraded, so the disposition callback can arrive with no peer. Since a softphone
    handles one call at a time, finalizing the most-recent OPEN call of that direction is
    unambiguous and correct in that case."""
    with _lock, _conn() as c:
        if peer:
            row = c.execute(
                "SELECT id FROM calls WHERE instance=? AND direction=? AND peer=? AND end_ts IS NULL "
                "ORDER BY start_ts DESC LIMIT 1", (str(instance), direction, peer)).fetchone()
        else:
            row = c.execute(
                "SELECT id FROM calls WHERE instance=? AND direction=? AND end_ts IS NULL "
                "ORDER BY start_ts DESC LIMIT 1", (str(instance), direction)).fetchone()
        if not row:
            return None
        c.execute("UPDATE calls SET status=?, end_ts=? WHERE id=?",
                  (status, int(time.time()), row["id"]))
        r = c.execute("SELECT * FROM calls WHERE id=?", (row["id"],)).fetchone()
        return dict(r) if r else None



def list_calls(instance: str, limit: int = 100) -> list:
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM calls WHERE instance=? ORDER BY start_ts DESC LIMIT ?",
            (str(instance), limit),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_calls(instance: str, ids: list[int]) -> int:
    """Delete specific call-log entries of this instance by id. Returns rows removed."""
    ids = [int(i) for i in ids]
    if not ids:
        return 0
    with _lock, _conn() as c:
        cur = c.execute(
            f"DELETE FROM calls WHERE instance=? AND id IN ({_placeholders(len(ids))})",
            (str(instance), *ids),
        )
        return cur.rowcount


def clear_calls(instance: str) -> int:
    """Delete the ENTIRE call log for this instance. Returns rows removed."""
    with _lock, _conn() as c:
        cur = c.execute("DELETE FROM calls WHERE instance=?", (str(instance),))
        return cur.rowcount
