#!/usr/bin/env python3
"""Offline unit tests for the P0/P2 swu_ike.py changes (run INSIDE the engine container where the
smartcard / CryptoMobile / card deps are importable):

    docker cp test_p0_p2.py <ctr>:/tmp/  &&  docker exec <ctr> sh -c 'cd /usr/local/bin && python3 /tmp/test_p0_p2.py'

Covers pure-logic pieces that don't need a live ePDG:
  P0-1  decode_payload_type_cp (R-bit mask, INTERNAL_IP6_SUBNET prefix_len at +20, short-attr
        guard) + _derive_ipv6_address_from_subnet (stable, in-prefix) + TIMEOUT_PERIOD raw decode
  P2-1  classify_create_child_request (ike_rekey / esp_rekey / additional_bearer / unknown)
  P2-2  map_deleted_esp_spis_to_ue_inbound (known/unknown SPI mapping)
  P2-4  encode_payload_type_sk fragmentation round-trip (SKF encode -> _handle_skf reassemble),
        in-order and out-of-order, plus single-SK unchanged path
"""
import os
import socket
import struct
import ipaddress
import sys

# keep timers/side effects inert during import/use
os.environ.setdefault("SWU_LIVENESS_PERIOD", "0")

import swu_ike
from swu_ike import (
    swu, CFG_REPLY, INTERNAL_IP6_SUBNET, INTERNAL_IP6_ADDRESS, P_CSCF_IP6_ADDRESS,
    TIMEOUT_PERIOD_FOR_LIVENESS_CHECK, IKE, ESP, SA, N, NINR, KE, TSI, TSR, SK,
    REKEY_SA, EPS_QOS, TFT, INITIAL_CONTACT, EAP_ONLY_AUTHENTICATION, INFORMATIONAL, NONE,
    ENCR_AES_CBC, AUTH_HMAC_SHA2_256_128,
)

FAILS = []
def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    if not cond:
        FAILS.append(name)


def make_obj():
    o = swu.__new__(swu)
    o.source_address = "10.0.0.1"
    o.epdg_address = "10.0.0.2"
    o.apn = "ims"
    o.com_port = "0"
    o.default_gateway = None
    o.mcc = "302"
    o.mnc = "220"
    o.imsi = "302220123456789"
    o.ki = o.op = o.opc = None
    o.netns_name = None
    o.sqn = None
    o.set_variables()
    return o


def test_cp_decode():
    print("P0-1 decode_payload_type_cp")
    o = make_obj()
    prefix = socket.inet_pton(socket.AF_INET6, "2001:db8:1:2::")
    pcscf = socket.inet_pton(socket.AF_INET6, "2001:db8:1:2::100")
    data = bytes([CFG_REPLY]) + b"\x00\x00\x00"
    # R-bit SET on the subnet attribute type -> must be masked off
    data += struct.pack("!H", 0x8000 | INTERNAL_IP6_SUBNET) + struct.pack("!H", 17) + prefix + bytes([64])
    data += struct.pack("!H", P_CSCF_IP6_ADDRESS) + struct.pack("!H", 16) + pcscf
    data += struct.pack("!H", TIMEOUT_PERIOD_FOR_LIVENESS_CHECK) + struct.pack("!H", 4) + struct.pack("!I", 30)
    res = o.decode_payload_type_cp(data)
    check("cfg_type == CFG_REPLY", res[0] == CFG_REPLY)
    subnet = [a for a in res[1] if a[0] == INTERNAL_IP6_SUBNET]
    check("subnet attr present (R-bit masked)", len(subnet) == 1)
    check("subnet prefix == 2001:db8:1:2::", subnet and subnet[0][1] == "2001:db8:1:2::")
    check("subnet prefix_len == 64 (read at +20)", subnet and subnet[0][2] == 64)
    tp = [a for a in res[1] if a[0] == TIMEOUT_PERIOD_FOR_LIVENESS_CHECK]
    check("TIMEOUT_PERIOD kept as raw 4 bytes", tp and isinstance(tp[0][1], (bytes, bytearray))
          and struct.unpack("!I", tp[0][1][:4])[0] == 30)
    # truncated final attribute -> must not raise, just stop
    bad = bytes([CFG_REPLY]) + b"\x00\x00\x00" + struct.pack("!H", INTERNAL_IP6_ADDRESS) + struct.pack("!H", 16) + b"\x00\x00"
    try:
        o.decode_payload_type_cp(bad)
        check("short attr does not raise", True)
    except Exception as e:
        check("short attr does not raise (%r)" % e, False)


def test_derive():
    print("P0-1 _derive_ipv6_address_from_subnet")
    o = make_obj()
    addr, plen = o._derive_ipv6_address_from_subnet("2001:db8:1:2::", 64)
    check("prefix_len honoured", plen == 64)
    check("address inside prefix",
          ipaddress.ip_address(addr) in ipaddress.ip_network("2001:db8:1:2::/64"))
    addr2, _ = o._derive_ipv6_address_from_subnet("2001:db8:1:2::", 64)
    check("address is STABLE across calls", addr == addr2)
    # different IMSI -> different IID
    o2 = make_obj(); o2.imsi = "302220000000000"
    addr3, _ = o2._derive_ipv6_address_from_subnet("2001:db8:1:2::", 64)
    check("address varies with IMSI", addr3 != addr)


def test_classify():
    print("P2-1 classify_create_child_request")
    o = make_obj()
    ike = [[SA, [1, IKE, b""]], [NINR, [b"n"]]]
    esp_rk = [[SA, [1, ESP, b"\x11\x11\x11\x11"]], [N, [ESP, REKEY_SA, b"\xaa\xaa\xaa\xaa", b""]]]
    add_qos = [[SA, [1, ESP, b"\x11\x11\x11\x11"]], [N, [ESP, EPS_QOS, b"", b"\x01"]]]
    add_plain = [[SA, [1, ESP, b"\x11\x11\x11\x11"]]]
    unk = [[NINR, [b"n"]]]
    check("IKE SA -> ike_rekey", o.classify_create_child_request(ike) == "ike_rekey")
    check("ESP + REKEY_SA -> esp_rekey", o.classify_create_child_request(esp_rk) == "esp_rekey")
    check("ESP + EPS_QOS (no rekey) -> additional_bearer",
          o.classify_create_child_request(add_qos) == "additional_bearer")
    check("ESP plain -> additional_bearer", o.classify_create_child_request(add_plain) == "additional_bearer")
    check("no SA -> unknown", o.classify_create_child_request(unk) == "unknown")


def test_spi_map():
    print("P2-2 map_deleted_esp_spis_to_ue_inbound")
    o = make_obj()
    o.spi_init_child = b"\x01\x01\x01\x01"
    o.spi_resp_child = b"\x02\x02\x02\x02"
    known, resp = o.map_deleted_esp_spis_to_ue_inbound([b"\x02\x02\x02\x02"])
    check("known peer SPI -> our inbound SPI", known and resp == [b"\x01\x01\x01\x01"])
    known2, resp2 = o.map_deleted_esp_spis_to_ue_inbound([b"\x09\x09\x09\x09"])
    check("unknown peer SPI -> all_known False", (not known2) and resp2 == [])
    # with an old (rekeyed-away) SA present too
    o.spi_init_child_old = b"\x03\x03\x03\x03"
    o.spi_resp_child_old = b"\x04\x04\x04\x04"
    known3, resp3 = o.map_deleted_esp_spis_to_ue_inbound([b"\x04\x04\x04\x04"])
    check("known old peer SPI -> old inbound SPI", known3 and resp3 == [b"\x03\x03\x03\x03"])


def _frag_setup(o, frag_size):
    o.negotiated_encryption_algorithm = ENCR_AES_CBC
    o.negotiated_integrity_algorithm = AUTH_HMAC_SHA2_256_128
    o.SK_EI = o.SK_ER = b"\x11" * 32
    o.SK_AI = o.SK_AR = b"\x22" * 32
    o.old_ike_message_received = False
    o.fragmentation_enabled = True
    o.peer_supports_fragmentation = True
    o.fragment_size = frag_size
    # decode_header only accepts a message whose SPIs match these — mirror the packet we build.
    o.ike_spi_initiator = b"\xAA" * 8
    o.ike_spi_responder = b"\xBB" * 8
    o.ike_spi_initiator_old = None
    o.ike_spi_responder_old = None


def _build_plaintext(o):
    # Several Notify payloads (~48 bytes of body) so a small fragment_size yields 3 fragments.
    types = [INITIAL_CONTACT, EAP_ONLY_AUTHENTICATION, INITIAL_CONTACT,
             EAP_ONLY_AUTHENTICATION, INITIAL_CONTACT, EAP_ONLY_AUTHENTICATION]
    body = b""
    for idx, t in enumerate(types):
        nxt = N if idx < len(types) - 1 else NONE
        body += o.encode_generic_payload_header(nxt, 0, o.encode_payload_type_n(0, b"", t))
    header = o.encode_header(b"\xAA" * 8, b"\xBB" * 8, N, 2, 0, INFORMATIONAL, (0, 0, 1), 7)
    return o.set_ike_packet_length(header + body)


def _reassemble(o, frags):
    o._frag_buf = {}
    o.ike_decoded_ok = False
    for f in frags:
        o.decode_ike(f)
    return o.ike_decoded_ok, getattr(o, "decoded_payload", None)


def test_fragmentation():
    print("P2-4 fragmentation round-trip")
    o = make_obj()
    _frag_setup(o, 20)  # body ~48 bytes -> 3 fragments
    ike_packet = _build_plaintext(o)
    frags = o.encode_payload_type_sk(ike_packet)
    check("returns a list of fragments", isinstance(frags, list) and len(frags) >= 2)
    check("every fragment IKE header next_payload == SKF",
          all(f[16] == swu_ike.SKF for f in frags))
    ok, dp = _reassemble(o, frags)
    check("in-order reassembly decodes", ok and dp and dp[0][0] == SK)
    if ok:
        notifies = [p[1][1] for p in dp[0][1] if p[0] == N]
        check("reassembled payloads contain INITIAL_CONTACT + EAP_ONLY",
              INITIAL_CONTACT in notifies and EAP_ONLY_AUTHENTICATION in notifies)
    ok2, dp2 = _reassemble(o, list(reversed(frags)))
    check("out-of-order reassembly decodes", ok2 and dp2 and dp2[0][0] == SK)

    # single-SK path unchanged when under threshold
    _frag_setup(o, 100000)
    sk = o.encode_payload_type_sk(ike_packet)
    check("large threshold -> single SK (bytes, not list)", isinstance(sk, (bytes, bytearray)))
    o.ike_decoded_ok = False
    o.decode_ike(sk)
    check("single SK decodes", o.ike_decoded_ok and o.decoded_payload[0][0] == SK)


def main():
    for t in (test_cp_decode, test_derive, test_classify, test_spi_map, test_fragmentation):
        try:
            t()
        except Exception as e:
            import traceback
            traceback.print_exc()
            FAILS.append("%s raised %r" % (t.__name__, e))
    print()
    if FAILS:
        print("FAILURES (%d): %s" % (len(FAILS), FAILS))
        sys.exit(1)
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
