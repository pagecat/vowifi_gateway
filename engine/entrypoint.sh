#!/bin/bash
# Engine entrypoint: render config -> hold PIN -> bring up ePDG tunnel -> discover
# P-CSCF -> start Asterisk (IMS registration + voice/SMS).
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
export USIM_PIN USIM_READER VOWIFI_ID MANAGER_URL VOWIFI_RUNDIR

# --- 2. Start PIN keeper and wait for the SIM to be usable ------------------------
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

# --- 3. Bring up strongSwan / ePDG tunnel ----------------------------------------
log "starting strongSwan..."
ipsec start
sleep 2
swanctl --load-creds || true
swanctl --load-conns || true
swanctl --initiate --child ims || true

# reconnect/backoff loop (like the reference)
(
  backoff=4
  while true; do
    sleep 5
    if ! swanctl --list-sas 2>/dev/null | grep -q '^ims:'; then
      log "ims SA down; re-initiating (backoff=$backoff)"
      if swanctl --initiate --child ims 2>/dev/null; then
        backoff=4
      else
        sleep "$backoff"; backoff=$((backoff*2)); [ "$backoff" -gt 120 ] && backoff=120
      fi
    fi
  done
) &

# --- 4. Wait for the tunnel, then discover P-CSCF and (re)render pjsip -------------
if [ -z "$(cat "$VOWIFI_RUNDIR/pcscf" 2>/dev/null)" ]; then
  log "waiting for IMS tunnel to establish..."
  for _ in $(seq 1 90); do
    swanctl --list-sas 2>/dev/null | grep -q 'INSTALLED' && break
    sleep 1
  done
  log "waiting for P-CSCF discovery..."
  for _ in $(seq 1 30); do
    # charon filelog line: "... received P-CSCF server IP 2001:568:ffff:3002::5"
    addr=$(grep -aoE 'received P-CSCF server IP [0-9a-fA-F:.]+' "$VOWIFI_RUNDIR/charon.log" 2>/dev/null \
           | head -1 | awk '{print $NF}')
    if [ -n "$addr" ]; then
      log "discovered P-CSCF: $addr"
      printf '%s' "$addr" > "$VOWIFI_RUNDIR/pcscf"
      /usr/local/bin/notify.py pcscf "$addr" 2>/dev/null || true
      python3 /usr/local/bin/render.py || true   # re-render pjsip.conf with pcscf
      break
    fi
    sleep 1
  done
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
