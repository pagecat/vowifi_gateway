"""
status.py - Per-instance status state machine with failure classification.

Returns a live snapshot: {state, label, reason_code, reason, detail}. The manager's
health tracker (main.py) overlays retry counters and, on exhaustion, an ERROR state.

States:      STOPPED, NO_CARD, PIN_PROBLEM, EPDG_UNRESOLVED, TUNNEL_DOWN, REGISTERING, OK
reason_code: machine key for the WebUI; `reason` is a user-friendly sentence.
detail:      raw signals (pin, pcscf, registration, ike classification) for advanced view.
"""
from __future__ import annotations

import re
import socket

from . import engine

LABELS = {
    "STOPPED": "Stopped",
    "NO_CARD": "No SIM card",
    "PIN_PROBLEM": "PIN error",
    "EPDG_UNRESOLVED": "Cannot resolve ePDG",
    "TUNNEL_DOWN": "Establishing VoWiFi tunnel",
    "REGISTERING": "Registering to IMS",
    "OK": "Working",
    "ERROR": "Failed",
}

# reason_code -> user-friendly message
REASONS = {
    "no_card": "No SIM card detected in the reader.",
    "pin_wrong": "SIM PIN is incorrect.",
    "pin_blocked": "SIM PIN is blocked — PUK required.",
    "epdg_unresolved": "Can't resolve the carrier's VoWiFi (ePDG) address — the carrier may "
                       "not support Wi-Fi Calling, or check DNS / internet connectivity.",
    "tunnel_network": "Can't establish the VoWiFi tunnel — network problem (no response from "
                      "the carrier's ePDG).",
    "tunnel_sim_auth": "Can't establish the VoWiFi tunnel — SIM authentication (EAP-AKA) was "
                       "rejected by the carrier.",
    "tunnel_proposal": "Can't establish the VoWiFi tunnel — the carrier rejected the encryption "
                       "settings (IKE proposal).",
    "tunnel_setup": "Establishing the VoWiFi (IPsec/ePDG) tunnel…",
    "registering": "VoWiFi tunnel is up — registering to the carrier's IMS…",
    "reg_rejected": "Can't register to the carrier's IMS (authentication or provisioning issue).",
    "ok": "Working — connected to the carrier over Wi-Fi.",
}


def resolve_epdg(fqdn: str) -> bool:
    try:
        socket.getaddrinfo(fqdn, None)
        return True
    except Exception:
        return False


def classify_ike(iid: str) -> tuple[str, str]:
    """Inspect recent charon (IKE) log to classify why the tunnel isn't up."""
    log = engine.charon_log(iid, 400)
    usim = engine.usim_status(iid)
    low = log.lower()
    # SIM auth failure (EAP-AKA)
    if usim.get("state") in ("AUTH_FAIL", "PIN_FAIL", "NO_CARD") or \
            "eap_aka failed" in low or "eap-aka failed" in low or \
            "authentication_failed" in low or "eap method eap_aka fail" in low or \
            "received auth_failed" in low or "authentication failed" in low:
        return "tunnel_sim_auth", REASONS["tunnel_sim_auth"]
    # Carrier rejected our crypto proposal / message
    if "invalid_syntax" in low or "no_proposal_chosen" in low or "invalid_ke" in low or \
            "no proposal" in low:
        return "tunnel_proposal", REASONS["tunnel_proposal"]
    # No response / retransmits -> network
    if "retransmit" in low or "giving up" in low or "no route" in low or \
            "destination unreachable" in low or "timeout" in low:
        return "tunnel_network", REASONS["tunnel_network"]
    # Not enough info yet -> still setting up
    return "tunnel_setup", REASONS["tunnel_setup"]


async def compute(inst: dict, ami_client=None) -> dict:
    iid = str(inst["id"])
    mcc, mnc = inst["mcc"], str(inst["mnc"]).zfill(3)
    epdg = inst.get("epdg") or f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"

    detail = {"msisdn": inst.get("msisdn") or None, "smsc": inst.get("smsc") or None,
              "iccid": inst.get("iccid") or None}

    def out(state, code):
        return {"state": state, "label": LABELS[state],
                "reason_code": code, "reason": REASONS.get(code, ""), "detail": detail}

    if not inst.get("enabled", True) or not engine.is_running(iid):
        return {"state": "STOPPED", "label": LABELS["STOPPED"],
                "reason_code": "stopped", "reason": "Stopped.", "detail": detail}

    pin = engine.read_run_json(iid, "pin_status.json") or {}
    detail["pin"] = pin
    pstate = pin.get("state")
    if pstate in (None, "NO_CARD"):
        return out("NO_CARD", "no_card")
    if pstate == "WRONG_PIN":
        return out("PIN_PROBLEM", "pin_wrong")
    if pstate == "PIN_BLOCKED":
        return out("PIN_PROBLEM", "pin_blocked")

    if not resolve_epdg(epdg):
        return out("EPDG_UNRESOLVED", "epdg_unresolved")

    if not engine.tunnel_installed(iid):
        code, _ = classify_ike(iid)
        r = out("TUNNEL_DOWN", code)
        detail["ike_reason"] = code
        return r

    detail["pcscf"] = engine.read_pcscf(iid)
    reg = "unknown"
    if ami_client is not None:
        reg = await ami_client.registration_state()
    detail["registration"] = reg
    if reg == "Registered":
        return out("OK", "ok")
    if reg == "Rejected":
        return out("REGISTERING", "reg_rejected")
    return out("REGISTERING", "registering")
