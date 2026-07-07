#!/bin/bash
# Engine entrypoint: render config -> hold PIN -> bring up the ePDG (SWu) tunnel with the
# pure-Python IKEv2/IPsec implementation (swu_ike.py) -> discover P-CSCF -> start Asterisk
# (IMS registration + voice/SMS).
#
# SWu tunnel: swu_ike.py (fasferraz/SWu-IKEv2, patched) is the sole ePDG tunnel path. It does
# IKEv2 + EAP-AKA (verifying the SIM PIN in its own PC/SC connection), userspace ESP over a
# tun device named "ipsec0" (so pjsip's bind_interface is unchanged), assigns the IPv6 inner
# address, and requests the IPv6 P-CSCF. A supervisor restarts it on exit; because every fresh
# start re-runs EAP-AKA WITH the PIN verify, the tunnel self-heals after a rekey/reauth teardown.
#
# PC/SC: this container is a pcscd CLIENT — it talks to the HOST pcscd via the bind-mounted
# /run/pcscd socket. The pcsc-lite client library is pinned to the same version as the host
# pcscd (see Dockerfile PCSC_VERSION) so the client/server protocol always matches.
set -u

export VOWIFI_RUNDIR="${VOWIFI_RUNDIR:-/run/vowifi}"
mkdir -p "$VOWIFI_RUNDIR" /logs /etc/asterisk

log() { echo "[entrypoint] $*"; }

# --- 1. Render configs from /config/instance.json --------------------------------
log "rendering configs..."
python3 /usr/local/bin/render.py || { log "render failed"; exit 1; }
# shellcheck disable=SC1091
set -a; . "$VOWIFI_RUNDIR/engine.env"; set +a
export USIM_PIN USIM_READER USIM_READER_INDEX USIM_IMSI VOWIFI_ID MANAGER_URL VOWIFI_RUNDIR
export SWU_SOURCE SWU_EPDG SWU_APN SWU_MCC SWU_MNC SWU_IMEI SWU_IMEISV SWU_CHILD_REKEY_MINUTES

# --- 2. Start PIN keeper and wait for the SIM to be usable ------------------------
# pin_keeper holds CHV1 verified for ami_usim's SIP IMS-AKA. swu_ike verifies the PIN itself
# in its own connection for EAP-AKA, so both auth paths work on PIN-enabled SIMs.
log "starting pin_keeper (reader=$USIM_READER)..."
python3 -u /usr/local/bin/pin_keeper.py &
KEEPER_PID=$!

wait_pin() {
    for _ in $(seq 1 30); do
        st=$(python3 -c "import json;print(json.load(open('$VOWIFI_RUNDIR/pin_status.json'))['state'])" 2>/dev/null || echo "")
        case "$st" in
            VERIFIED|PIN_DISABLED) log "PIN state: $st"; return 0 ;;
            WRONG_PIN|PIN_BLOCKED) log "PIN problem: $st - continuing (manager will surface)"; return 1 ;;
        esac
        sleep 1
    done
    log "PIN keeper did not reach VERIFIED in time - continuing anyway"
    return 1
}
wait_pin || true

# --- 3. Bring up the SWu (python IKEv2/IPsec) tunnel, supervised ------------------
log "starting SWu IKEv2 tunnel (epdg=$SWU_EPDG apn=$SWU_APN reader=$USIM_READER_INDEX)..."
: > "$VOWIFI_RUNDIR/charon.log"      # fresh IKE log for control-plane classification
rm -f "$VOWIFI_RUNDIR/swu.ctl" "$VOWIFI_RUNDIR/swu_status.json"

# swu_ike is very chatty (per-packet IKE decode dumps). Send ITS stdout+stderr ONLY to the IKE
# log (run/charon.log) so it does not intermix with Asterisk's console on the container stdout
# (docker logs) — the manager surfaces the IKE log and the Asterisk log as two separate views.
# The supervisor's own status lines still go to the container stdout via log().
(
  backoff=4
  while true; do
    log "swu_ike starting"
    python3 -u /usr/local/bin/swu_ike.py \
        -m "${USIM_READER_INDEX:-0}" \
        -s "$SWU_SOURCE" \
        -d "$SWU_EPDG" \
        -a "${SWU_APN:-ims}" \
        -I "$USIM_IMSI" \
        -M "$SWU_MCC" \
        -N "$SWU_MNC" \
        -E "${SWU_IMEI:-}" \
        -V "${SWU_IMEISV:-}" >> "$VOWIFI_RUNDIR/charon.log" 2>&1
    rc=$?
    log "swu_ike exited (rc=$rc); reconnecting in ${backoff}s"
    sleep "$backoff"; backoff=$((backoff*2)); [ "$backoff" -gt 60 ] && backoff=60
  done
) &
SWU_PID=$!

# --- 4. Wait for the tunnel, then (re)render pjsip with the discovered P-CSCF ------
log "waiting for SWu tunnel to establish..."
for _ in $(seq 1 90); do
  st=$(python3 -c "import json;print(json.load(open('$VOWIFI_RUNDIR/swu_status.json'))['state'])" 2>/dev/null || echo "")
  [ "$st" = "CONNECTED" ] && { log "SWu tunnel CONNECTED"; break; }
  sleep 1
done

log "waiting for P-CSCF discovery..."
for _ in $(seq 1 30); do
  [ -s "$VOWIFI_RUNDIR/pcscf" ] && break
  sleep 1
done
addr=$(cat "$VOWIFI_RUNDIR/pcscf" 2>/dev/null)
if [ -n "$addr" ]; then
  log "discovered P-CSCF: $addr"
  python3 /usr/local/bin/render.py || true   # re-render pjsip.conf with pcscf
  # Seed the applied-marker so swu_ike's in-process P-CSCF watcher only re-renders + reloads
  # Asterisk on a LATER change (reconnect/reauth), not redundantly right after this render.
  printf '%s' "$addr" > "$VOWIFI_RUNDIR/pcscf.applied"
else
  log "no P-CSCF discovered yet - continuing (manager will surface tunnel state)"
fi

# --- 5. Start USIM<->AMI bridge and Asterisk -------------------------------------
log "starting ami_usim bridge..."
python3 -u /usr/local/bin/ami_usim.py /usr/local/etc/ami_usim.ini &

# Enable the SIP message logger once Asterisk is ready (retry until it takes), so the
# P-Associated-URI (registered MSISDN) and SIP traces are captured for the manager/Logs.
( for _ in $(seq 1 40); do
    sleep 3
    asterisk -rx "pjsip set logger on" 2>/dev/null | grep -qi "enabled" && break
  done ) &

log "starting Asterisk..."
exec asterisk -f
